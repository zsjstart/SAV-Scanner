#!/usr/bin/env python3
import os
import concurrent.futures
from itertools import groupby
from collections import defaultdict, Counter
import pandas as pd
from ipid_prediction_lib import single_ipid_test_for_spoof
import ipaddress
import random
import glob
import pickle


def load_vantage_points(ifile):

    servers = list()
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0]
            asn = fields[1].strip('\n')
            if not validate_ip_address(ip) or len(ip.split('.')) != 4:
                continue
            servers.append((ip, asn))

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


def get_neighbors(asn, ASrel):
    neighbors = dict()
    for p in ASrel[asn]['providers']:
        neighbors[p] = 1
    for c in ASrel[asn]['customers']:
        neighbors[c] = 1
    for p in ASrel[asn]['peers']:
        neighbors[p] = 1
    return neighbors


def get_fake_ip_01(neighbors, neighborASN, neighborASN_neighbors, ASpref):
    fake_ip = None
    for n in neighbors:
        if n == neighborASN or n in neighborASN_neighbors:
            continue
        if int(n) not in ASpref:
            continue
        pref = list(ASpref[int(n)])[0]
        fake_ip = pref.split('/')[0]
        break
    return fake_ip


def get_fake_ip_02(asn, neighborASN, neighbors, ASrel, ASpref):
    fake_ip = None
    for n in neighbors:
        if n == neighborASN:
            continue
        if int(n) not in ASpref:
            continue
        if (neighborASN in ASrel[asn]['customers'] or neighborASN in ASrel[asn]['peers']) and n in ASrel[neighborASN]['customers']:
            pref = list(ASpref[int(n)])[0]
            fake_ip = pref.split('/')[0]
            break

        if neighborASN in ASrel[asn]['providers']:
            pref = list(ASpref[int(n)])[0]
            fake_ip = pref.split('/')[0]
            break

    return fake_ip


def get_fake_ip_03(asn, ASrel, ASpref):
    fake_ip = None
    customers = list(ASrel[asn]['customers'])
    random.shuffle(customers)
    for c in customers:
        if int(c) not in ASpref:
            continue
        pref = list(ASpref[int(c)])[0]
        fake_ip = pref.split('/')[0]
        break

    return fake_ip


def ip_spoof_via_ipids(ip, asn, ofile, proto, port, flag, ns, ASrel, ASpref):
    dataset = {}
    status1, status2 = '', ''
    sip0, sip1 = '45.125.236.166', '45.125.236.167'  # 166 and 167, 72 and 74
    if asn not in ASrel:
        return
    typ = ASrel[asn]['type']
    if typ == 'stub':
        # ofile.write(ip+','+asn+','+typ+','+status1+'\n')
        return

    
    neighbors = get_neighbors(asn, ASrel)

    infos, hops = mtr_cmd(proto, ip, port)  # hops = [AS1234, AS???]

    if hops == None:
        return
    hops.reverse()
    if len(hops) < 2:
        return
    neighborAS = hops[1]
    if '???' in neighborAS:
        return
    neighborASN = neighborAS.split('AS')[1]
    if neighborASN not in neighbors:
        return

    # Here we select an IP as the spoofed source address

    neighborASN_neighbors = get_neighbors(neighborASN, ASrel)
    '''

    '''
    fake_ip = get_fake_ip_01(neighbors, neighborASN, neighborASN_neighbors, ASpref)
    
    if fake_ip == None:
        return
    code, status1 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status1 == None:
        return
    ofile.write(ip+','+asn+','+typ+','+status1+'\n')
    '''
    '''
    fake_ip = get_fake_ip_02(asn, neighborASN, neighbors, ASrel, ASpref)

    if fake_ip == None:
        return
    code, status2 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status2 == None:
        return
    
    '''
    fake_ip = get_fake_ip_03(asn, ASrel, ASpref)
    if fake_ip == None:
        return
    code, status3 = single_ipid_test_for_spoof(
        '', '', sip0, sip1, ip, fake_ip, proto, port, flag, ns, 30, True, dataset, ofile)

    if status3 == None:
        return

    ofile.write(ip+','+asn+','+typ+','+status3+'\n')
    '''


def validate_ip_address(ip_string):
    try:
        ip_object = ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def uRPF_measure():
    path = './uRPF/'

    with open(path+'asn_cls_and_rel.p', "rb") as f:
        ASrel = pickle.load(f)
    with open(path+'prefixes_to_as.p', "rb") as f:
        ASpref = pickle.load(f)
    # icmp_infra_vps.sav.dat: ipv4/24 networks with status = 3 (SAV in place)
    files = os.path.join(path, "*_infra_vps.sav.dat")
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
                path+note+'_infra_urpf_measure.0'+str(i)+'.res', 'w')
            ips = load_vantage_points(ifile)
            random.shuffle(ips)

            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                for ip, asn in ips:
                    futures.append(executor.submit(
                        ip_spoof_via_ipids, ip, asn, ofile, proto, port, flag, ns, ASrel, ASpref))
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


def data_analysis_for_sav():
    types = get_asn_types()
    path = '../uRPF/results/sav/'  # ./Datasets/urpf/
    files = os.path.join(path, "all_infra_urpf_measure.sav.res")
    files = glob.glob(files)
    res = defaultdict(list)
    net2ips = defaultdict(set)
    ofile = open(path+'sav_measure.res', 'w')
    #ofile2 = open('../uRPF/zombies/'+'icmp_infra_vps.rest.dat', 'w')
    #ofile3 = open('../uRPF/zombies/'+'tcp_random_infra_vps.rest.dat', 'w')
    count = 0
    asnres = defaultdict(set)
    ips, asns, nets, stubnets = set(), set(), set(), set()
    nstub = 0
    for ifile in files:
        print(ifile)
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
                t = fields[2]

                r = fields[-1].strip('\n')
                if r == '' and t == 'stub':
                    stubnets.add(asn)
                    continue

                ips.add(ip)
                nets.add(net)
                asns.add(asn)

                if r == 'spoofable':
                    code = 1

                elif r == 'non-spoofable':
                    code = 2

                res[(net, asn, t)].append(code)

    status = 0
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
    # ofile2.close()
    # ofile3.close()
    print('Total number of results: ', count)
    print('Total number of IPV4/24: ', len(res))
    print(len(ips), len(nets), len(asns))
    print('Total number of stub nets: ', len(stubnets))
    print('spoofable /24 networks: ', n1)
    print('non-spoofable /24 networks: ', n2)
    print('spoofable ASes: ', len(asnres[1]))
    print('non-spoofable ASes: ', len(asnres[2]))


def data_analysis_for_urpf():
    types = get_asn_types()
    path = '../uRPF/results/urpf/'  # ./Datasets/urpf/
    files = os.path.join(path, "all_infra_urpf_measure.urpf.res")
    files = glob.glob(files)
    res = defaultdict(list)
    net2ips = defaultdict(set)
    ofile = open(path+'urpf_measure.res', 'w')
    #ofile2 = open('../uRPF/zombies/'+'icmp_infra_vps.rest.dat', 'w')
    #ofile3 = open('../uRPF/zombies/'+'tcp_random_infra_vps.rest.dat', 'w')
    count = 0
    asnres = defaultdict(set)
    ips, asns, nets, stubnets = set(), set(), set(), set()
    nstub = 0
    for ifile in files:
        print(ifile)
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
                t = fields[2]

                r = fields[-1].strip('\n')
                if r == '' and t == 'stub':
                    stubnets.add(asn)
                    continue

                ips.add(ip)
                nets.add(net)
                asns.add(asn)

                if r == 'spoofable':
                    code = 1

                elif r == 'non-spoofable':
                    code = 2

                res[(net, asn, t)].append(code)

    status = 0
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
    # ofile2.close()
    # ofile3.close()
    print('Total number of results: ', count)
    print('Total number of IPV4/24: ', len(res))
    print(len(ips), len(nets), len(asns))
    print('Total number of stub nets: ', len(stubnets))
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


def compute_statistics_for_sav():
    path = '../uRPF/results/sav/'
    res = defaultdict(set)
    types = defaultdict(set)
    overallres = defaultdict(set)
    urpf = set()
    n = 0
    ofile = open(path+'ACL_present_asn.res', 'w')
    with open(path + 'sav_measure.res', 'r') as filehandle:
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

            status = 'ACL'  # 1: spoofable - ACL 2: non-spoofable - uRPF
            if int(code) == 2:
                status = 'uRPF'
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
            if states[0] == 'uRPF':
                n2 = n2 + 1
            else:
                n3 = n3 + 1
                ofile.write(asn+'\n')
    print('uRPF and ACL, uRPF, ACL: ', n1, n2, n3)
    ofile.close()


def compute_statistics_for_urpf():
    path = '../uRPF/results/urpf/'
    res = defaultdict(set)
    types = defaultdict(set)
    overallres = defaultdict(set)
    urpf = set()
    n = 0
    ofile = open(path+'strict_uRPF_present_asn.res', 'w')
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

            # 1: spoofable - ACL/feasible uRPF 2: non-spoofable - strict_uRPF
            status = 'ACL/feasible uRPF'
            if int(code) == 2:
                status = 'strict_uRPF'
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
            if states[0] == 'ACL/feasible uRPF':
                n2 = n2 + 1
            else:
                n3 = n3 + 1
                ofile.write(asn+'\n')
    print('strict uRPF and ACL/feasible, ACL/feasible uRPF, strict_uRPF: ', n1, n2, n3)
    ofile.close()


def compute_statistics_for_aggregate():
    path = '../uRPF/results/'
    res = defaultdict(set)
    overallres = defaultdict(set)
    n_acl, n_feasible, n_strict = 0, 0, 0
    ofile1 = open(path+'ACL_present_asn.res', 'w')
    ofile2 = open(path+'feasible_present_asn.res', 'w')
    ofile3 = open(path+'strict_present_asn.res', 'w')
    ofile4 = open(path+'urpf_present_asn.res', 'w')
    with open(path + 'sav_urpf_measure.res', 'r') as filehandle:
        filecontents = filehandle.readlines()

        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 5:
                continue
            #ip = fields[0]
            # 81.26.144.122,81.26.144.0,8641,1
            net = fields[0]
            asn = fields[1]
            t = fields[2]
            code1 = fields[3]
            code2 = fields[4].strip('\n')

            if code1 == '1':

                overallres[(asn, t)].add('ACL')
            elif code1 == '2':
                if code2 == '1':

                    overallres[(asn, t)].add('feasible')
                elif code2 == '2':

                    overallres[(asn, t)].add('strict')

    n0, n1, n2, n3 = 0, 0, 0, 0
    for asn, t in overallres:
        states = list(overallres[(asn, t)])
        # print(states)
        if len(states) >= 2:
            print(states)
            n0 = n0 + 1  # 'partly spoofable'
            res[('Hybrid', t)].add(asn)
            ofile4.write(asn+'\n')
        else:
            if states[0] == 'ACL':
                n1 = n1 + 1
                res[('ACL', t)].add(asn)
                ofile1.write(asn+'\n')
            elif states[0] == 'feasible':
                res[('feasible', t)].add(asn)
                n2 = n2 + 1
                ofile2.write(asn+'\n')
                ofile4.write(asn+'\n')
            elif states[0] == 'strict':
                res[('strict', t)].add(asn)
                n3 = n3 + 1
                ofile3.write(asn+'\n')
                ofile4.write(asn+'\n')
    for code, t in res:
        print(code, t, len(res[(code, t)]))

    print('Hybrid, ACL, feasible uRPF, strict_uRPF: ', n0, n1, n2, n3)
    ofile1.close()
    ofile2.close()
    ofile3.close()
    ofile4.close()


def combine_sav_urpf():
    sav = dict()
    path = '../uRPF/results/sav/'
    with open(path + 'sav_measure.res', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue

            net = fields[0]
            asn = fields[1]
            t = fields[2]
            code1 = fields[-1].strip('\n')
            sav[(net, asn, t)] = code1
    res = dict()
    ofile = open('../uRPF/results/sav_urpf_measure.res', 'w')
    path = '../uRPF/results/urpf/'
    with open(path + 'urpf_measure.res', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue

            net = fields[0]
            asn = fields[1]
            t = fields[2]
            code2 = fields[-1].strip('\n')
            if (net, asn, t) not in sav:
                code1 = ''
            else:
                code1 = sav[(net, asn, t)]
            res[(net, asn, t)] = (code1, code2)
    for k in sav:
        if k in res:
            continue
        code1 = sav[k]
        code2 = ''
        res[k] = (code1, code2)
    for net, asn, t in res:
        code1, code2 = res[(net, asn, t)]
        ofile.write(net+','+asn+','+t+','+code1+','+code2+'\n')
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
    uRPF_measure()
    
    # data_analysis_for_sav()
    # data_analysis_for_urpf()
    # compute_statistics_for_sav()
    # compute_statistics_for_urpf()
    # compute_statistics_for_aggregate()

    # email_results_analysis()
    # compute_email_statistics()
    # combine_sav_urpf()
