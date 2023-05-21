#!/usr/bin/env python3
import os
import concurrent.futures
from itertools import groupby
from collections import defaultdict, Counter
import pandas as pd
#from ipid_censor_or_spoof_lib import single_ipid_test_for_spoof
import ipaddress
import random
import glob


def load_vantage_points(ifile):

    servers = list()
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0].strip('\n')
            if not validate_ip_address(ip) or len(ip.split('.')) != 4:
                continue
            servers.append(ip)

    return servers


def parse_report(report, dst_ip):
    infos = defaultdict(set)
    hops = list()
    ips = list()
    with open(report, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(",")
            ip = fields[5]
            asn = fields[6]
            infos[asn].add(ip)
            hops.append(asn)
            ips.append(ip)

        if ips[-1] != dst_ip:
            return None, None
        for i, h in enumerate(hops):
            if i == 0 or i == len(hops) - 1:
                continue
            if '???' in h and hops[i-1] == hops[i+1]:
                hops[i] = hops[i-1]

        hops = [k for k, g in groupby(hops)]

    return infos, hops


# mtr -n 122.114.110.209 --tcp -P 80 -G 1 -Z 1 -c 3 -z -i 0.3 -r -C > mtr_report
def mtr_cmd(proto, dst_ip, dst_port):
    infos, hops = None, None
    try:

        report = "./output/"+dst_ip+"_mtr.rep"
        if proto == 'icmp':
            proto = ''
        else:
            proto = '--'+proto
        cmd = """ mtr -n %s %s -P %s -G 1 -Z 1 -c 3 -z -i 0.3 -r -C > %s""" % (
            dst_ip, proto, dst_port, report)
        os.system(cmd)
        infos, hops = parse_report(report, dst_ip)
        cmd = """ rm %s""" % (report)
        os.system(cmd)

    except Exception as err:
        print("error - > ", err)
        return None, None
    return infos, hops


def get_one_fake_ip(ip):
    g = ip.split(".")
    if len(g) < 4:
        return
    fake_ip = g[0] + '.' + g[1]+'.' + g[2]+'.'+str((int(g[3])+1) % 256)
    return fake_ip


def ip_spoof_via_ipids(ip, ofile, proto, port, flag, ns):
    dataset = {}
    
    '''
    #bogon IP spoofing
    sip0, sip1 = '45.125.236.166', '45.125.236.167'  # 166 and 167, 72 and 74

    fake_ip = "192.0.2.1"  # 192.0.2.0/24
    code, status1 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status1 == None:
        return
    ofile.write(ip+','+status1+'\n')
    '''
    
    fake_ip = get_one_fake_ip(ip)
    code, status2 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status2 == None:
        return

    infos, hops = mtr_cmd(proto, ip, port)  # hops = [AS1234, AS???]

    if hops == None:
        return
    hops.reverse()
    neighborAS = None
    for hop in hops[1:]:
        if '???' in hop:
            continue
        else:
            neighborAS = hop
            break
    if neighborAS == None:
        return
    nip = list(infos[neighborAS])[0]
    fake_ip = get_one_fake_ip(nip)
    #fake_ip = nip
    code, status3 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status3 == None:
        return
    ofile.write(ip+','+status2+','+status3+'\n')
    


def validate_ip_address(ip_string):
    try:
        ip_object = ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def SAV_measure():
    path = './uRPF/'
    files = os.path.join(path, "*_public_vps_uni.dat")
    files = glob.glob(files)
    for i in range(1, 6):
        for ifile in files:
            note, proto, port, flag, ns = '', '', int(
                80), 'SA', 'www.google.com'

            if 'icmp' in ifile:
                proto = 'icmp'
                note = proto
            elif 'tcp_random' in ifile:
                proto = 'tcp'
                port = int(random.randrange(10000, 65535, 1))
                note = 'tcp_random'
            elif 'tcp_public' in ifile:
                proto = 'tcp'
                port = int(80)
                note = 'tcp_public'
            elif 'udp' in ifile:
                proto = 'udp'
                port = int(53)
                note = proto

            print('ifile: ', ifile, proto, port)
            # if os.path.isfile(path+note+'_infra_urpf_measure.twospoofs.0'+str(i)+'.res'): continue
            ofile = open(
                path+note+'_public_urpf_measure.two_spoofs.0'+str(i)+'.res', 'w')
            ips = load_vantage_points(ifile)
            random.shuffle(ips)
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                for ip in ips:
                    futures.append(executor.submit(
                        ip_spoof_via_ipids, ip, ofile, proto, port, flag, ns))
                for future in concurrent.futures.as_completed(futures):
                    future.result()


def SAV_measure_v2():
    path = './'
    files = os.path.join(path, "")
    files = glob.glob(files)
    for ifile in files:
        note, proto, port, flag, ns = '', '', int(80), 'SA', 'www.google.com'

        if 'icmp' in ifile:
            proto = 'icmp'
            note = proto
        elif 'tcp_random' in ifile:
            proto = 'tcp'
            port = int(random.randrange(10000, 65535, 1))
            note = 'tcp_random'
        elif 'tcp' in ifile:
            proto = 'tcp'
            port = int(80)
            note = proto
        elif 'udp' in ifile:
            proto = 'udp'
            port = int(53)
            note = proto

        print('ifile: ', ifile, proto, port)
        ofile = open('./'+note+'_public_urpf_measure.05.res', 'w')
        ips = load_vantage_points(ifile)

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for ip in ips:
                futures.append(executor.submit(
                    ip_spoof_via_ipids, ip, ofile, proto, port, flag, ns))
            for future in concurrent.futures.as_completed(futures):
                future.result()


def get_asn_types():
    types = dict()
    with open('./three_types_asns.data', 'r') as filehandle:
        filecontents = filehandle.readlines()

        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 2:
                continue
            asn = fields[0]
            t = fields[1].strip('\n')
            types[asn] = t
    return types


def email_results_analysis():
    types = get_asn_types()
    path = './Datasets/urpf/'
    ofile = open(path+'SAV_email_res_asn_type.dat', 'w')
    with open(path+'SAV_email_res_asn.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            asn = fields[0].strip('\n')
            t = types[asn]
            ofile.write(asn+','+t+'\n')
    ofile.close()


def data_analysis_twospoofs():
    types = get_asn_types()
    path = '../uRPF/results/twospoofs/'  # ./Datasets/urpf/
    files = os.path.join(path, "*_infra_urpf_measure.twospoofs.asns.res")
    files = glob.glob(files)
    res = defaultdict(list)
    net2ips = defaultdict(set)
    ofile = open(path+'urpf_measure.res', 'w')
    ofile2 = open('../uRPF/zombies/'+'icmp_infra_vps.sav.transit.dat', 'w')
    ofile3 = open('../uRPF/zombies/' +
                  'tcp_random_infra_vps.sav.transit.dat', 'w')
    count = 0
    ips, asns, nets = set(), set(), set()

    for ifile in files:

        with open(ifile, 'r') as filehandle:
            filecontents = filehandle.readlines()
            count = count + len(filecontents)
            for i, line in enumerate(filecontents):
                fields = line.split(",")
                if len(fields) < 1:
                    continue
                ip = fields[0]
                net = ip.split('.')
                net[-1] = '0'
                net = '.'.join(net)
                asn = fields[1]
                cu = fields[2]
                ips.add(ip)
                nets.add(net)
                asns.add(asn)
                if asn not in types:
                    t = 'unknown'
                else:
                    t = types[asn]
                res1 = fields[-2]
                res2 = fields[-1].strip('\n')
                if res1 == 'spoofable' and res2 == 'spoofable':
                    code = 1
                elif res1 == 'spoofable' and res2 == 'non-spoofable':
                    code = 2
                elif res1 == 'non-spoofable' and res2 == 'spoofable':
                    code = 3
                elif res1 == 'non-spoofable' and res2 == 'non-spoofable':
                    code = 4
                res[(net, asn, t)].append(code)
                net2ips[net].add(ip)

    status = 0
    savs = set()
    sav_nets = set()
    sav_ips = set()
    for net, asn, t in res:

        counts = Counter(res[(net, asn, t)])
        samples = list()
        for k in counts:
            samples.append((k, counts[k]))
        samples.sort(key=lambda a: a[1])

        if len(samples) >= 2 and samples[-1][1] == 1:  # len(samples) >= 2 and

            status = 0
            # continue
        else:
            status = samples[-1][0]
        if status == 3:
            savs.add(asn)
            sav_nets.add(net)

            for ip in net2ips[net]:
                sav_ips.add(ip)
                if t == 'transit' or t == 'tier-1':
                    ofile2.write(ip+','+asn+'\n')
                    ofile3.write(ip+','+asn+'\n')

        out = ','.join(map(str, [net, asn, t, status]))
        ofile.write(out+'\n')
    ofile.close()
    ofile2.close()
    ofile3.close()
    print('sav, nets, ips: ', len(savs), len(sav_nets), len(sav_ips))
    print('Total number of results: ', count)
    print('Total number of IPV4/24: ', len(res))
    print(len(ips), len(nets), len(asns))


def data_analysis_bogon():
    types = get_asn_types()
    path = '../uRPF/results/bogon/'  # ./Datasets/urpf/
    files = os.path.join(path, "all_infra_urpf_measure.bogon.asns.res")
    files = glob.glob(files)
    res = defaultdict(list)
    net2ips = defaultdict(set)
    asnres = defaultdict(set)
    ofile = open(path+'urpf_measure.res', 'w')

    count = 0
    ips, asns, nets = set(), set(), set()

    for ifile in files:

        with open(ifile, 'r') as filehandle:
            filecontents = filehandle.readlines()
            count = count + len(filecontents)
            for i, line in enumerate(filecontents):
                fields = line.split(",")
                if len(fields) < 1:
                    continue
                ip = fields[0]
                net = ip.split('.')
                net[-1] = '0'
                net = '.'.join(net)
                asn = fields[1]
                cu = fields[2]
                ips.add(ip)
                nets.add(net)
                asns.add(asn)
                if asn not in types:
                    t = 'unknown'
                else:
                    t = types[asn]
                r = fields[-1].strip('\n')
                if r == 'spoofable':
                    code = 1

                elif r == 'non-spoofable':
                    code = 2

                res[(net, asn, t)].append(code)
                net2ips[net].add(ip)

    status = 0
    savs = set()
    n1, n2 = 0, 0
    for net, asn, t in res:

        counts = Counter(res[(net, asn, t)])
        samples = list()
        for k in counts:
            samples.append((k, counts[k]))
        samples.sort(key=lambda a: a[1])

        if len(samples) >= 2 and samples[-1][1] == 1:  # len(samples) >= 2 and

            status = 0
            # continue
        else:
            status = samples[-1][0]

        if status == 1:
            n1 = n1 + 1
        if status == 2:
            n2 = n2 + 1
        asnres[status].add(asn)
        out = ','.join(map(str, [net, asn, t, status]))
        ofile.write(out+'\n')
    ofile.close()

    print('Total number of results: ', count)
    print('Total number of IPV4/24: ', len(res))
    print(len(ips), len(nets), len(asns))
    print('spoofable /24 networks: ', n1)
    print('non-spoofable /24 networks: ', n2)
    print('spoofable ASes: ', len(asnres[1]))
    print('non-spoofable ASes: ', len(asnres[2]))


def filter_ips():
    path = '/home/zhao/Shujie/uRPF/zombies/'
    icmp_ips = dict()
    tcp_ips = dict()
    common_ips = dict()
    n = 0
    of1 = open(path+'icmp_infra_vps.uni.dat', 'w')
    of2 = open(path+'tcp_random_infra_vps.uni.dat', 'w')
    of3 = open(path+'icmp_tcp_random_infra_vps.mini.dat', 'w')
    with open(path + 'icmp_infra_vps.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print(len(filecontents))
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0].strip('\n')
            icmp_ips[ip] = 1

    with open(path + 'tcp_random_infra_vps.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print(len(filecontents))
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0].strip('\n')
            tcp_ips[ip] = 1
    for ip in icmp_ips:
        if ip in tcp_ips:
            common_ips[ip] = 1
            of3.write(ip+'\n')
    print(len(common_ips))
    for ip in icmp_ips:
        if ip in common_ips:
            continue
        of1.write(ip+'\n')
    for ip in tcp_ips:
        if ip in common_ips:
            continue
        of2.write(ip+'\n')
    of1.close()
    of2.close()
    of3.close()


def filter_ips02():
    path = '/home/zhao/Shujie/uRPF/zombies/'
    types = get_asn_types()
    checked = dict()
    n = 0
    asns, cus, tys = set(), set(), defaultdict(set)
    #of = open(path+'infra_servers.all,new02.dat', 'w')
    with open(path + 'all_infra_vps.asns.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print(len(filecontents))
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0]
            asn = fields[1]
            cu = fields[2].strip('\n')
            if asn not in types:
                t = 'unknown'
            else:
                t = types[asn]

            if ip in checked:
                continue
            # of.write(ip+'\n')
            checked[ip] = 1
            asns.add(asn)
            if cu == '':
                continue
            cus.add(cu)
            tys[t].add(asn)

    print(len(checked), len(asns), len(cus))
    # of.close()
    for t in tys:
    	print(t, len(tys[t]))


def compute_statistics_for_twospoofs():
    path = '../uRPF/results/twospoofs/'
    #path = './Datasets/urpf/'
    res = defaultdict(set)
    types = defaultdict(set)
    overallres = defaultdict(set)
    urpf = set()
    netres, asnres = defaultdict(set), defaultdict(set)
    ofile = open(path+'problematic_SAV_present_asn.res', 'w')
    n = 0
    with open(path + 'urpf_measure.res', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print('Total results: ', len(filecontents))
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue
            #ip = fields[0]
            # 81.26.144.122,81.26.144.0,8641,1
            net = fields[0]
            asn = fields[1]
            t = fields[2]
            code = fields[3].strip('\n')
            if int(code) == 0:  # before I comment this out, leading to different results!!!
                n = n + 1
                continue
            netres[code].add(net)
            asnres[code].add(asn)
            if int(code) == 3:
                urpf.add(asn)
            status = 'non-SAV'
            if int(code) == 3 or int(code) == 4:
                status = 'SAV'
            res[(code, t)].add(asn)
            types[t].add(asn)
            overallres[asn].add(status)
    for code in netres:
        print(code, len(netres[code]))
    for code in asnres:
        print(code, len(asnres[code]))

    for code, t in res:
        print(code, t, len(res[(code, t)]))
    for t in types:
        print(t, len(types[t]))

    n1, n2, n3 = 0, 0, 0
    for asn in overallres:
        states = list(overallres[asn])

        if len(states) == 2:
            n1 = n1 + 1  # 'partly spoofable'
            ofile.write(asn+'\n')
        else:
            if states[0] == 'non-SAV':
                n2 = n2 + 1
                ofile.write(asn+'\n')
            else:
                n3 = n3 + 1

    print('inconsistent results: ', n)
    print('partly SAV, non-SAV, SAV, urpf: ', n1, n2, n3, len(urpf))
    ofile.close()


def compute_statistics_for_bogon():
    path = '../uRPF/results/bogon/'
    res = defaultdict(set)
    types = defaultdict(set)
    overallres = defaultdict(set)
    urpf = set()
    n = 0
    ofile = open(path+'looseuRPF_present_asn.res', 'w')
    with open(path + 'urpf_measure.res', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print('Total results obtained: ', len(filecontents))
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue
            #ip = fields[0]
            # 81.26.144.122,81.26.144.0,8641,1
            net = fields[0]
            asn = fields[1]
            t = fields[2]
            code = fields[3].strip('\n')
            if int(code) == 0:
                n = n + 1
                continue

            status = 'non-looseuRPF'  # 1: spoofable
            if int(code) == 2:
                status = 'looseuRPF'
            res[(code, t)].add(asn)
            types[t].add(asn)
            overallres[asn].add(status)
    print('Inconsistent IPv4/24 networks: ', n)
    for code, t in res:
        print(code, t, len(res[(code, t)]))
    for t in types:
        print(t, len(types[t]))

    n1, n2, n3 = 0, 0, 0
    for asn in overallres:
        states = list(overallres[asn])
        # print(states)
        if len(states) == 2:
            n1 = n1 + 1  # 'partly spoofable'
        else:
            if states[0] == 'non-looseuRPF':
                n2 = n2 + 1
            else:
                n3 = n3 + 1
                ofile.write(asn+'\n')
    print('partly looseuRPF, non-looseuRPF, looseuRPF: ', n1, n2, n3)
    ofile.close()


def compute_email_statistics():
    path = './Datasets/urpf/'
    files = os.path.join(path, "SAV_present_asn_emails.res")
    files = glob.glob(files)
    count = 0
    asns = set()
    for f in files:

        with open(f) as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                email = line.split(' ')[-1].strip('\n')
                asn = line.split(' ')[2]

                if email == '\'\'':
                    continue
                count = count + 1
                asns.add(asn)
                print(asn)
    print(count, len(asns))


if __name__ == "__main__":
    # execute only if run as a script
    SAV_measure()
    # data_analysis_bogon()
    # data_analysis_twospoofs()
    # compute_statistics_for_twospoofs()
    # compute_statistics_for_bogon()
    # email_results_analysis()
    # compute_email_statistics()
