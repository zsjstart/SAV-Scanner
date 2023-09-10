#!/usr/bin/env python3

from numpy import array, asarray
import numpy as np
from ipid_prediction_lib import *
from sklearn.metrics import mean_squared_error
from math import sqrt
from sklearn import datasets, preprocessing
import time
import decimal
import threading
import concurrent.futures
import pandas as pd
import math
import statistics
from scipy.stats import norm, linregress
import random
import csv
from sklearn import linear_model
from scipy.optimize import fsolve
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import RBF, DotProduct, WhiteKernel, ConstantKernel as C
import re
import glob
import os
from ipwhois import IPWhois

#from ipid_online_analysis_lr import predict_ipids
import multiprocessing
from caproto.sync.shark import shark
import dpkt
import parse_pcap
from ctypes import *
import warnings
import logging
warnings.filterwarnings("ignore")

#import seaborn as sns
#import matplotlib.pyplot as plt

#cols = sns.color_palette("colorblind")
# sns.set_theme(style="darkgrid")


class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]


def extract(string_arr):
    arr = []
    matches = re.findall(regex, string_arr)
    for match in matches:
        arr.append(int(match))
    return arr


def modify(times):
    start = times[0]
    i = 0
    for time in times:
        times[i] = int(round(float(time - start)/1000000.0))
        i += 1
    return times


def computeIpidVelocity(ids, times, MAX):

    spd = float(0)

    for i in range(0, len(ids)-1):

        gap = float(rela_diff(ids[i], ids[i+1], MAX))
        # dur = float(times[i+1]-times[i])/1000000000.0 #unit: ID/s
        dur = float(times[i+1]-times[i])
        spd += gap/dur

    spd /= float(len(ids)-1)

    return round(spd, 3)


def computeIpidVelocity02(ids, times, MAX):
    id_seg = list()
    time_seg = list()
    vels = list()
    for i in range(len(ids)):
        id_seg.append(ids[i])
        time_seg.append(times[i])
        if len(id_seg) == 3:
            vel = computeIpidVelocity(id_seg, time_seg, MAX)
            vels.append(vel)
            id_seg = []
            time_seg = []
    return np.median(vels)


def computeIpidVelocitySeg(ids, times, MAX):
    id_segment = []
    time_segment = []
    vels = []
    for i in range(len(ids)):
        if math.isnan(ids[i]):
            if len(id_segment) >= 3:
                vel = computeIpidVelocity(id_segment, time_segment, MAX)
                vels.append(vel)
            id_segment = []
            time_segment = []
            continue
        id_segment.append(ids[i])
        time_segment.append(times[i])
    if len(id_segment) >= 3:  # without NAN
        vel = computeIpidVelocity(id_segment, time_segment, MAX)
        vels.append(vel)
    if len(vels) == 2 and len(id_segment) > len(ids)/2:
        return vels[1]
    return np.median(vels)


def computeIpidVelocityNan(ids, times, MAX):
    id_segment = []
    time_segment = []
    for i in range(len(ids)):
        if math.isnan(ids[i]):
            continue
        id_segment.append(ids[i])
        time_segment.append(times[i])
    vel = computeIpidVelocity(id_segment, time_segment, MAX)
    return vel


def count_ipid_wraps(data):
    count = 0
    for i in range(0, len(data)-1):
        if data[i+1]-data[i] < 0:
            count = count + 1
    return count


def series_to_supervised(data, n_in=1, n_out=1, dropnan=True):
    n_vars = 1 if type(data) is list else data.shape[1]
    df = DataFrame(data)
    cols = list()
    # input sequence (t-n, ... t-1)
    for i in range(n_in, 0, -1):
        cols.append(df.shift(i))

    # forecast sequence (t, t+1, ... t+n)
    for i in range(0, n_out):
        cols.append(df.shift(-i))

    # put it all together
    agg = concat(cols, axis=1)
    # print(agg)
    # drop rows with NaN values
    if dropnan:
        agg.dropna(inplace=True)
    return agg.values


def obtain_restore_data(sequence, diff_data):
    base_data = list()
    restore_data = list()
    for i in range(3, len(diff_data)):
        if math.isnan(diff_data[i-3]+diff_data[i-2]+diff_data[i-1]+diff_data[i]):
            continue
        base_data.append(sequence[i])
        restore_data.append(sequence[i+1])
    return base_data, restore_data

# split a univariate dataset into train/test sets


def train_test_split(data, n_test):
    return data[:-n_test, :], data[-n_test:, :]

# split a univariate sequence into samples


def split_sequence(sequence, n_steps):
    X, y = list(), list()
    for i in range(len(sequence)-n_steps):
        # find the end of this pattern
        end_ix = i + n_steps
        # gather input and output parts of the pattern
        seq_x, seq_y = sequence[i:end_ix], sequence[end_ix]
        X.append(seq_x)
        y.append(seq_y)
    return array(X), array(y)


def sMAPE02(chps_ind, actual, predictions):
    res = list()
    for i in range(len(actual)):
        if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
            if predictions[i] < actual[i]:
                predictions[i] = predictions[i] + 65536
                #res.append(2 * abs(pre-actual[i]) / (actual[i] + pre))
            else:
                actual[i] = actual[i] + 65536
                #res.append(2 * abs(predictions[i]-ac) / (ac + predictions[i]))
            continue
        if (actual[i] + predictions[i]) != 0:
            if (actual[i] + predictions[i]) < 0:
                continue
            res.append(
                2 * abs(predictions[i]-actual[i]) / (actual[i] + predictions[i]))
        else:
            res.append(0)
    after_res = list()
    for v in res:
        if math.isnan(v):
            continue
        after_res.append(v)
    return np.mean(after_res)


def MAPE(chps_ind, actual, predictions):
    res = list()
    for i in range(len(actual)):
        if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
            if predictions[i] < actual[i]:
                pre = predictions[i] + 65536
                res.append(abs(pre-actual[i]) / actual[i])
            else:
                ac = actual[i] + 65536
                res.append(abs(predictions[i]-ac) / ac)
            continue
        if (actual[i] + predictions[i]) != 0:
            if (actual[i] + predictions[i]) < 0:
                continue
            res.append(abs(predictions[i]-actual[i]) / actual[i])
        else:
            res.append(0)
    after_res = list()
    for v in res:
        if math.isnan(v):
            continue
        after_res.append(v)
    return np.mean(after_res)


def filter_outliersv2(outlier, sequence, thr, MAX, actual, outlier_ind):
    change = False
    new_window = [i for i in sequence]
    if not outlier:
        return new_window, change
    if len(actual) == len(new_window):
        n = 0
    else:
        n = len(new_window)-3
    for i in range(n, len(new_window)-2):
        mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
        if containNAN(mini_window):
            continue
        if alarm_turning_point(thr, mini_window[0], mini_window[1], MAX):
            mini_window[1] = (mini_window[1] + MAX)
        if alarm_turning_point(thr, mini_window[1], mini_window[2], MAX):
            mini_window[2] = (mini_window[2] + MAX)
        delta1 = rela_diff(mini_window[0], mini_window[1], MAX)
        delta2 = rela_diff(mini_window[1], mini_window[2], MAX)
        if delta1 > thr or delta2 > thr:  # suitable for two consecutive outliers
            mini_window = array(mini_window)
            med = np.median(mini_window)
            mini_window = abs(mini_window - med)
            max_index = max((v, i) for i, v in enumerate(mini_window))[1]

            if i+max_index == 0:  # process the outliers detected
                new_window[i+max_index] = new_window[1]
            else:
                new_window[i+max_index] = new_window[i+max_index-1]
            outlier_ind.append(len(actual)-len(new_window)+i+max_index)
            if len(outlier_ind) >= 3:
                if (outlier_ind[-1] - outlier_ind[-2]) == 1 and (outlier_ind[-2] - outlier_ind[-3]) == 1:
                    new_window[i] = actual[i+len(actual)-len(new_window)]
                    new_window[i+1] = actual[i+1+len(actual)-len(new_window)]
                    new_window[i+2] = actual[i+2+len(actual)-len(new_window)]
                    outlier_ind.clear()
                    change = True
    return new_window, change


def alarm_turning_point(thr, a1, a2, MAX):
    alarm = False
    delta = a2 - a1
    # a2-a1+MAX approximates to a2 (close to 1 in ideal)
    if delta < 0 and rela_diff(a1, a2, MAX) < thr:
        alarm = True
    return alarm


def eliminate_trans_error(chps_ind, actual, predictions):
    diff = list()
    for i in range(len(actual)):
        # if the turning point is predicted with a prior second, then the main prediction error is on the upper turining point, otherwise, th error is on the lower turning point.
        if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
            if predictions[i] < actual[i]:
                diff.append(predictions[i]-actual[i] + 65536)
            else:
                diff.append(predictions[i]-actual[i] - 65536)
            continue
        diff.append(predictions[i]-actual[i])
    return diff


def containNAN(data):
    for i in range(len(data)):
        if math.isnan(data[i]):
            return True
    return False


def countNans(data):
    num = 0
    for i in range(len(data)-2):
        if math.isnan(data[i]):
            if math.isnan(data[i+1]) and math.isnan(data[i+2]):
                num = 3
                return num
    return num


def data_preprocess(thr, history, MAX):
    data = [i for i in history]
    wraps = list()
    for i in range(len(data)-1):
        if data[i+1] - data[i] < 0 and rela_diff(data[i], data[i+1], MAX) < thr:
            wraps.append(i+1)
    for _, i in enumerate(wraps):
        for t in range(i, len(data)):
            data[t] = data[t] + MAX
    return wraps, data


def one_time_forecast(data, times, ntime, k, predictions, MAX):
    X = np.array(times).reshape(-1, 1)
    y = np.array(data)
    model = linear_model.LinearRegression().fit(X, y)
    nt = np.array(ntime).reshape(-1, 1)
    y_pred = model.predict(nt)[0] - MAX*k
    predictions.append(y_pred)


def group_ips_measure(ips, protocol, port, cus, pfxs, domains, dst_ip, dst_port, td, l, spoof, dataset):
    for ip, cu, pfx, ns in zip(ips, cus, pfxs, domains):
        controlled_experiment(ip, protocol, port, cu, pfx,
                              ns, dst_ip, dst_port, td, l, spoof, dataset)


def group_ips_measure_old(ip, cu, pfx):
    protocol = 'tcp'
    port = random.randrange(10000, 65535, 1)
    #port = 80
    dst_ip = '199.244.49.62'
    td = random.randrange(1, 2, 1)  # 1, 2, 3, 4
    dst_port = 80
    l = 30
    spoof = False
    print(ip, cu, pfx)
    controlled_experiment(ip, protocol, port, cu, pfx, '',
                          dst_ip, dst_port, td, l, spoof, None)  # ns = ''


def probe(sip, ipv4, protocol, flag, port, ns):
    port = str(port)

    sip = bytes(sip, 'utf-8')
    ipv4 = bytes(ipv4, 'utf-8')
    protocol = bytes(protocol, 'utf-8')
    flag = bytes(flag, 'utf-8')
    ns = bytes(ns, 'utf-8')
    port = bytes(port, 'utf-8')

    sip = go_string(c_char_p(sip), len(sip))
    ip = go_string(c_char_p(ipv4), len(ipv4))
    proto = go_string(c_char_p(protocol), len(protocol))
    flag = go_string(c_char_p(flag), len(flag))
    ns = go_string(c_char_p(ns), len(ns))
    port = go_string(c_char_p(port), len(port))

    a = lib.probe(sip, ip, proto, flag, port, ns)
    return a


def spoofing_probe(ipv4, protocol, port, ns, dst_ip, dst_port, n, flag):
    ipv4 = bytes(ipv4, 'utf-8')
    protocol = bytes(protocol, 'utf-8')
    ns = bytes(ns, 'utf-8')
    dst_ip = bytes(dst_ip, 'utf-8')
    flag = bytes(flag, 'utf-8')
    n = bytes(n, 'utf-8')
    port = bytes(port, 'utf-8')
    dst_port = bytes(dst_port, 'utf-8')

    ip = go_string(c_char_p(ipv4), len(ipv4))
    proto = go_string(c_char_p(protocol), len(protocol))
    ns = go_string(c_char_p(ns), len(ns))
    dst_ip = go_string(c_char_p(dst_ip), len(dst_ip))
    n = go_string(c_char_p(n), len(n))
    flag = go_string(c_char_p(flag), len(flag))
    port = go_string(c_char_p(port), len(port))
    dst_port = go_string(c_char_p(dst_port), len(dst_port))
    lib.spoofing_probe(ip, dst_ip, proto, port, dst_port,
                       ns, n, flag)  # port: reflector port


def control_measure(sip, dst_ip, dst_port, flag, r, n):
    sip = bytes(sip, 'utf-8')
    dst_ip = bytes(dst_ip, 'utf-8')
    dst_port = bytes(dst_port, 'utf-8')
    flag = bytes(flag, 'utf-8')
    r = bytes(r, 'utf-8')

    sip = go_string(c_char_p(sip), len(sip))
    dst_ip = go_string(c_char_p(dst_ip), len(dst_ip))
    dst_port = go_string(c_char_p(dst_port), len(dst_port))
    flag = go_string(c_char_p(flag), len(flag))
    r = go_string(c_char_p(r), len(r))
    code = lib.controlMeasureForIpid(sip, dst_ip, dst_port, flag, r, n)
    return code


def spoofing_samples(diff_data):
    # when the estimated error is the maximum of previous errors, maybe an abnormal value when there is ana outlier
    e = np.max(diff_data, axis=-1)
    u = np.mean(diff_data)
    s = np.std(diff_data)
    # if s == 0: # to keep the trend monotonously increasing
    #	n = 5
    # else:

    n = 1+int(2.06*s+e-u)  # > 1.64 when p = 0.05, 2.06 when p = 0.02

    # next, set p2
    '''n2 = 2*n
	y2 = round(fsolve(func, 2.1, xtol=10.**-20, args=(n2, e, u, s))[0], 4)
	p2 = norm.cdf(-y2)'''
    return n, u, s, e


def func(x, *args):
    try:
        n, e, u, s = args
        return 1+int(x*s+e-u) - n
    except Exception as err:
        logging.error(err)
        return None


def is_open_port(u, s, e, n):

    if s == 0:

        if abs(e) >= n:
            return True
        else:
            return False

    v = (e-u)/s
    if norm.cdf(v) <= 0.02:  # p = 0.02
        return True
    return False


def detect01(err, p, u, s, n):
    status1 = 'abnormal'
    status2 = 'normal'
    status3 = 'undetectable'
    if math.isnan(err):
        return status3
    if s == 0:
        if abs(err) >= n:
            return status1
        else:
            return status2

    v = (err-u)/s
    if norm.cdf(v) <= p:  # p = 0.02
        return status1
    return status2


def detect02(errs, p, u, s, n):
    status1 = 'no blocked'
    status2 = 'outbound blocking'
    status3 = 'undetectable'
    for err in errs:
        if math.isnan(err):
            return status3
    res = list()
    for err in errs:
        res.append(detect01(err, p, u, s, n))
    c = 0
    for r in res:
        if r == 'abnormal':
            c = c+1
    if c >= 1:  # at least one
        return status2
    return status1


def detect_new(err1, p, err2, u, s, n):
    status1 = 'Inbound blocking'
    status2 = 'No blocked'
    status3 = 'Outbound blocking'
    status4 = 'Unkonwn'
    '''if s == 0:
		if abs(err1) < n: #abs(err4) < n
			return status1
		elif n <= abs(err1)  and abs(err4) < n: # abs(err1) < 2*n
			return status2
		elif n <= abs(err1)  and abs(err4) >= n:
			return status3
		else:
			return status4
	
	p_e1 = norm.cdf((err1-u)/s)
	p_e4 = norm.cdf((err4-u)/s)
	if p_e1 > p: #p_e4 > p1
		return status1
	elif p_e1 <= p and p_e4 > p: # p2 < p_e1 <= p1
		return status2
	elif p_e1 <= p and p_e4 <= p: #  p2 < p_e1 <= p1
		return status3
	else:
		return status4'''
    st1 = detect01(err1, p, u, s, n)
    st2 = detect01(err2, p, u, s, n)
    if st1 == 'normal':
        return status1
    elif st1 == 'abnormal' and st2 == 'normal':
        return status2
    elif st1 == 'abnormal' and st2 == 'abnormal':
        return status3
    else:
        return status4


def test_dst_port(label, url, ip, protocol, flag, port, ns):
    count = 0
    status = 'open'
    for i in range(2):
        ipid = probe(ip, protocol, flag, port, ns)
        if ipid == -1:
            count = count+1
        time.sleep(1)
    if count == 2:
        status = 'closed'
    return status, label, url, ip, port


def pre_processing(sequence, MAX):
    diff_data = difference(sequence, 1, MAX)
    diff_data = array(diff_data).reshape(-1, 1)
    scaler = preprocessing.MinMaxScaler()
    # scaling the input and output data to the range of (0,1)
    diff_data = scaler.fit_transform(diff_data)
    minimum = scaler.data_min_
    maximum = scaler.data_max_
    return diff_data, maximum, minimum


def gp_one_time_forecast(sequence, predictions, MAX):
    diff_data, maximum, minimum = pre_processing(sequence, MAX)
    X = np.array(range(len(sequence)-1)).reshape(-1, 1)  # for time
    y = np.array(diff_data)
    #kernel = DotProduct() + WhiteKernel()
    # kernel = C(constant_value=10, constant_value_bounds=(1e-2, 1e3))*RBF(length_scale=1e2, length_scale_bounds=(1, 1e3)) Not suitable!!!
    # kernel = DotProduct() #this kernel cannot deal witht the abrupt changes or outliers (i.g., noise), but is well-suited for the linear changes
    #kernel = DotProduct()
    kernel = WhiteKernel()
    # kernel = WhiteKernel() #noise_level=0.3**2, noise_level_bounds=(0.1**2, 0.5**2)
    warnings.filterwarnings("ignore")
    gp = GaussianProcessRegressor(kernel=kernel)  # n_restarts_optimizer=5
    gp.fit(X, y)
    nt = np.array(len(sequence)).reshape(-1, 1)
    y_pred, sigma = gp.predict(nt, return_std=True)
    y_pred = denormalize(y_pred, maximum, minimum)
    prediction = (y_pred[0] + sequence[-1]) % MAX
    predictions.append(prediction[0])


def my_compute_td(sip, server):
    dst_ip = server[1]
    dst_port = int(server[2])
    sip = bytes(sip, 'utf-8')
    sip = go_string(c_char_p(sip), len(sip))
    dst_ip = bytes(dst_ip, 'utf-8')
    dst_ip = go_string(c_char_p(dst_ip), len(dst_ip))
    td = lib.myComputeTd(sip, dst_ip, dst_port)
    return td


def compute_td(sip, dst_ip, dst_port):
    td = 0
    try:

        pcapFile = "./retran_time_"+dst_ip+".pcap"
        parse_pcap.run(dst_ip, dst_port, pcapFile)
        td = parse_pcap.parse_pcap(pcapFile)
        
        parse_pcap.remove(pcapFile)
    except Exception as err:
        logging.error(err)
    return td


def controlled_experiment(ip, protocol, port, cu, pfx, ns, dst_ip, dst_port, td, plth, spoof, dataset):
    code = 0
    count = 0
    for i in range(3):
        ipid = probe(ip, protocol, 'SA', port, ns)
        if ipid <= 0:
            count = count+1  # -1 or 0
    if count == 3:
        logging.info('Client unreachable: {a}'.format(a=ip))
        code = 1
        return code, dst_ip
    '''res = predict_ipids(ip, protocol,'SA', port, ns, 1, 10) # fs = 1, sl = 10
	if res != 1:
		logging.info('Not applicable: {a}, {res}'.format(a= ip, res=res))
		code = 1'''

    sliding_window = list()
    pr = 1
    wlth = 5
    plth = plth
    mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
    emax = 0.0
    p2 = 0.02
    flag = 'control'
    ipids = list()
    actual = list()
    predictions = list()
    chps_ind = list()
    outlier_ind = list()
    tem_actual = list()
    while True:
        ipid = probe(ip, protocol, 'SA', port, ns)
        start = time.monotonic()
        ipids.append(ipid)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        tem_actual.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(ipid)
            sliding_window.pop(0)
        if len(predictions) == plth-1:
            diff = eliminate_trans_error(chps_ind, actual, predictions)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)

            if len(after_diff) < (plth-1) * 0.7:
                #logging.info('Invalid: {a}, {b}'.format(a= ip, b = actual))
                code = 1
                return code, dst_ip
            mae = np.mean(abs(array(after_diff)))
            smape = sMAPE02(chps_ind, actual, predictions)
            n, u, s, emax = spoofing_samples(after_diff)
            #print('n, p2: ', n, p2)
            # f.write(ip+','+str(smape)+','+str(n)+'\n')
            if n > 10:
                # logging.info('n>10, require retest: {a}'.format(a= ip)) # 10
                code = 1
                return code, dst_ip
            if spoof:
                # test_pred_n, port should be random
                spoofing_probe(dst_ip, protocol, dst_port,
                               ns, ip, port, n, flag)
        '''if len(predictions) == plth-1+td:
			if spoof:
				spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
		'''
        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.5:
                predictions.append(math.nan)
                time.sleep(pr)
                continue
            times = list()
            for i in range(len(sliding_window)):
                times.append(i)
            tHistory = times
            MAX = 65536

            outlier = True
            if len(predictions) >= plth:
                outlier = False

            if containNAN(sliding_window):
                vel = computeIpidVelocityNan(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact

            if vel < 1000:
                thr = 15000  # experimentially specify the threshold
            else:
                thr = 30000
            if vel > 10000:
                outlier = False  # For high fluctuating

            # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
            if len(predictions) > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                chps_ind.append(i-2)
                chps_ind.append(i-1)

            if len(predictions) == plth+td:
                break

            sliding_window = fill_miss_values(sliding_window)

            sliding_window, _ = filter_outliersv2(
                outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)

            #gp_one_time_forecast(sliding_window, predictions, MAX)
            # identify the truning point and make a preprocessing
            wraps, new_window = data_preprocess(thr, sliding_window, MAX)
            k = len(wraps)
            ntime = tHistory[-1]+1
            one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)

            if predictions[-1] < 0:
                predictions[-1] = 0

        #lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
        time.sleep(pr)
        #end = time.monotonic()
        #elapsed = end-start
        # print(elapsed)
    diff = eliminate_trans_error(chps_ind, actual, predictions)
    # here design a test: no error, manually subtract n to the predcition errors
    err1 = diff[-(td+1)]
    p = 0.02
    err2 = diff[-1]
    status = None
    status = detect_new(err1, p, err2, u, s, n)
    #print('status: ', status, n)

    '''dataset['cu'].append(cu)
	dataset['pfx'].append(pfx)
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['status'].append(status)
	dataset['dst_ip'].append(dst_ip)'''
    f.write(cu+','+pfx+','+ip+','+status+'\n')
    #logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
    return code, dst_ip


def test_ipids(ip, protocol, port, ns):
    code = 0
    count = 0
    for i in range(3):
        ipid = probe(ip, protocol, 'SA', port, ns)
        if ipid <= 0:
            count = count+1  # -1 or 0
    if count == 3:
        logging.info('Client unreachable: {a}'.format(a=ip))
        code = 1
        return code
    res = predict_ipids(ip, protocol, 'SA', port, ns, 1, 10)  # fs = 1, sl = 10
    if res != 1:
        logging.info('Not applicable: {a}, {res}'.format(a=ip, res=res))
        code = 1
    return code


def single_ipid_test_for_spoof(cu, asn, sip0, sip1, ip, fake_ip, protocol, port, flag, ns, plth, spoof, dataset, ofile):
    code = 0
    sliding_window = list()
    pr = 1
    wlth = 5
    plth = plth
    mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
    emax = 0.0
    p2 = 0.02
    # note = 'test'  # 'S'
    note = 'control'
    ipids = list()
    actual = list()
    predictions = list()
    chps_ind = list()
    outlier_ind = list()
    tem_actual = list()
    i = 0
    sip = sip0
    status = None
    while True:
        if i % 2 == 0:
            sip = sip0
        else:
            sip = sip1
        ipid = probe(sip, ip, protocol, flag, port, ns)
        if ipid == 0  or (len(sliding_window)>=2 and sliding_window[0] == sliding_window[1]):
            code = 1
            return code, status
            
        i = i + 1

        start = time.monotonic()
        ipids.append(ipid)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        tem_actual.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(ipid)
            sliding_window.pop(0)
        if len(predictions) == plth-1:
            diff = eliminate_trans_error(chps_ind, actual, predictions)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)

            if len(after_diff) < (plth-1) * 0.7:
                logging.info('Invalid: {a}, {b}'.format(a=ip, b=actual))
                code = 1
                return code, status
            mae = np.mean(abs(array(after_diff)))
            smape = sMAPE02(chps_ind, actual, predictions)
            pr = 1 - smape
            if pr < 0.9:
                code = 1
                return code, status
            n, u, s, emax = spoofing_samples(after_diff)
            #print('n, p2: ', n, p2)
            # f.write(ip+','+str(smape)+','+str(n)+'\n')

            if n > 100 or n < 1:
                logging.info('n>100, require retest: {a}'.format(a=ip))  # 10
                code = 1
                return code, status
            if spoof:
                # spoofing_probe(ip, protocol, port, ns, dst_ip, dst_port, n, flag) # port should be random
                # here should be a public ipv4 server from the same AS
                dst_ip = fake_ip
                #dst_ip = '45.155.130.1'
                dst_port = port
                # test_pred_n, port should be random
                spoofing_probe(dst_ip, protocol, str(dst_port),
                               ns, ip, str(port), str(n), note)

        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.5:
                predictions.append(math.nan)
                time.sleep(pr)
                continue
            times = list()
            for i in range(len(sliding_window)):
                times.append(i)
            tHistory = times
            MAX = 65536

            outlier = True
            if len(predictions) >= plth:
                outlier = False

            if containNAN(sliding_window):
                vel = computeIpidVelocityNan(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact

            if vel < 1000:
                thr = 15000  # experimentially specify the threshold
            else:
                thr = 30000
            if vel > 10000:
                outlier = False  # For high fluctuating

            # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
            if len(predictions) > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                chps_ind.append(i-2)
                chps_ind.append(i-1)

            if len(predictions) == plth:
                break

            #sliding_window = fill_miss_values(sliding_window)

            #sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)

            gp_one_time_forecast(sliding_window, predictions, MAX)

            # identify the turning point and make a preprocessing
            wraps, new_window = data_preprocess(thr, sliding_window, MAX)
            k = len(wraps)
            ntime = tHistory[-1]+1
            one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)

            if predictions[-1] < 0:
                predictions[-1] = 0

        #lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
        time.sleep(pr)
        #end = time.monotonic()
        #elapsed = end-start

    diff = eliminate_trans_error(chps_ind, actual, predictions)
    if math.isnan(diff[-1]):
        logging.info('Packet loss: {a}'.format(a=ip))
        code = 1
        return code, status
    err = diff[-1]  # err is always negative.

    if is_open_port(u, s, err, n):
        status = 'spoofable'
    else:
        status = 'non-spoofable'

    # ofile.write(cu+','+asn+','+ip+','+status+'\n')
    #logging.info('{a} | {b} | {c} | {d}'.format(a=ip, b=dst_ip, c=actual, d=predictions))
    return code, status


def measure_server(sip0, ip, protocol, flag, port, ns):
    count = 0
    code = 0
    for i in range(3):
        ipid = probe(sip0, ip, protocol, flag, port, ns)

        if ipid < 0:
            count = count+1  # -1
    if count == 3:
        code = 1  # unreachable
        return code
    return code


def single_ipid_test_for_censor(cu, asn, sip0, sip1, server_ip, server_port, server_td, ip, protocol, port, flag, ns, plth, spoof, dataset, ofile):
    code = 0
    status = 'Unknown'
    
    td = server_td
    sliding_window = list()
    pr = 1
    wlth = 5
    plth = plth
    mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
    emax = 0.0
    p = 0.02
    note = 'test'  # 'S'
    #note = 'control'
    ipids = list()
    actual = list()
    predictions = list()
    chps_ind = list()
    outlier_ind = list()
    tem_actual = list()
    i = 0
    sip = sip0

    code = measure_server(sip0, server_ip, 'tcp', 'S', server_port, '')
    if code == 1:
        status = 'Unalive'
        return code, status, server_ip
    while True:
        if i % 2 == 0:
            sip = sip0
        else:
            sip = sip1
            
        ipid = probe(sip, ip, protocol, flag, port, ns)
        if ipid == 0  or (len(sliding_window)>=2 and sliding_window[0] == sliding_window[1]):
            code = 1
            status = 'Unapplicable'
            return code, status, server_ip
            
        i = i + 1

        start = time.monotonic()
        ipids.append(ipid)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        tem_actual.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(ipid)
            sliding_window.pop(0)
        if len(predictions) == plth-1:
            diff = eliminate_trans_error(chps_ind, actual, predictions)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)

            if len(after_diff) < (plth-1) * 0.7:
                status = "Unverified"
                code = 1
                return code, status, server_ip
            mae = np.mean(abs(array(after_diff)))
            smape = sMAPE02(chps_ind, actual, predictions)

            n, u, s, emax = spoofing_samples(after_diff)
            #print('spoofed samples: ', n)
            if n > 100 or n < 1:
                # logging.info('n>100, require retest: {a}'.format(a=ip))  # 10
                status = "Unverified"
                code = 1
                return code, status, server_ip
            
            if spoof:
                dst_ip = server_ip
                dst_port = server_port
                # test_pred_n, port should be random
                spoofing_probe(ip, protocol, str(port),
                               ns, dst_ip, str(dst_port), str(n), note)
                

        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.5:
                predictions.append(math.nan)
                time.sleep(pr)
                continue
            times = list()
            for i in range(len(sliding_window)):
                times.append(i)
            tHistory = times
            MAX = 65536

            outlier = True
            if len(predictions) >= plth:
                outlier = False

            if containNAN(sliding_window):
                vel = computeIpidVelocityNan(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact

            if vel < 1000:
                thr = 15000  # experimentially specify the threshold
            else:
                thr = 30000
            if vel > 10000:
                outlier = False  # For high fluctuating

            # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
            if len(predictions) > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                chps_ind.append(i-2)
                chps_ind.append(i-1)

            if len(predictions) == plth+td:
                break

            
            sliding_window = fill_predicted_values(sliding_window, predictions)
            sliding_window = fill_miss_values(sliding_window)
            #if len(predictions) >= plth:
            #	sliding_window[-1] = predictions[-1]

            #sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)

            gp_one_time_forecast(sliding_window, predictions, MAX)

            '''
            # identify the turning point and make a preprocessing
            wraps, new_window = data_preprocess(thr, sliding_window, MAX)
            k = len(wraps)
            ntime = tHistory[-1]+1
            one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)
            '''

            if predictions[-1] < 0:
                predictions[-1] = 0

        #lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
        time.sleep(pr)
        #end = time.monotonic()
        #elapsed = end-start

    diff = eliminate_trans_error(chps_ind, actual, predictions)
    err1 = diff[-(td+1)]
    err2 = diff[-1]
    if math.isnan(err1) or math.isnan(err2):
        status = "Unverified"
        code = 1
        return code, status, server_ip
    status = detect_new(err1, p, err2, u, s, n)

    return code, status, server_ip


def single_ipid_test_for_censor_old(cu, asn, ip, protocol, port, ns, cls, dst_ip, dst_port, plth, spoof, td, dataset, ofile):
    code = 0
    #astatus = test_dst_port(dst_ip, protocol, 'S', dst_port, ns)
    sip = "45.125.236.166"
    sliding_window = list()
    pr = 1
    wlth = 5
    plth = plth
    mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
    emax = 0.0
    p2 = 0.02
    flag = 'test'
    ipids = list()
    actual = list()
    predictions = list()
    chps_ind = list()
    outlier_ind = list()
    tem_actual = list()
    while True:
        ipid = probe(ip, protocol, 'SA', port, ns)
        start = time.monotonic()
        ipids.append(ipid)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        tem_actual.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(ipid)
            sliding_window.pop(0)
        if len(predictions) == plth-1:
            diff = eliminate_trans_error(chps_ind, actual, predictions)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)

            if len(after_diff) < (plth-1) * 0.7:
                logging.info('Invalid: {a}, {b}'.format(a=ip, b=actual))
                code = 1
                return code, dst_ip
            mae = np.mean(abs(array(after_diff)))
            smape = sMAPE02(chps_ind, actual, predictions)
            n, u, s, emax = spoofing_samples(after_diff)
            #print('n, p2: ', n, p2)
            # f.write(ip+','+str(smape)+','+str(n)+'\n')
            if n > 10:
                logging.info('n>10, require retest: {a}'.format(a=ip))  # 10
                code = 1
                return code, dst_ip
            if spoof:
                spoofing_probe(ip, protocol, port, ns, dst_ip,
                               dst_port, n, flag)  # port should be random
                # spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.5:
                predictions.append(math.nan)
                time.sleep(pr)
                continue
            times = list()
            for i in range(len(sliding_window)):
                times.append(i)
            tHistory = times
            MAX = 65536

            outlier = True
            if len(predictions) >= plth:
                outlier = False

            if containNAN(sliding_window):
                vel = computeIpidVelocityNan(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact

            if vel < 1000:
                thr = 15000  # experimentially specify the threshold
            else:
                thr = 30000
            if vel > 10000:
                outlier = False  # For high fluctuating

            # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
            if len(predictions) > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                chps_ind.append(i-2)
                chps_ind.append(i-1)

            if len(predictions) == plth+td:
                break

            sliding_window = fill_miss_values(sliding_window)

            #sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)

            gp_one_time_forecast(sliding_window, predictions, MAX)

            '''wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)'''

            if predictions[-1] < 0:
                predictions[-1] = 0

        #lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
        time.sleep(pr)
        #end = time.monotonic()
        #elapsed = end-start
        # print(elapsed)
    diff = eliminate_trans_error(chps_ind, actual, predictions)
    if math.isnan(diff[-1]) or math.isnan(diff[-4]):
        logging.info('Packet loss: {a}'.format(a=ip))
        code = 1
        return code, dst_ip
    # here design a test: no error, manually subtract n to the predcition errors
    err1 = diff[-(td+1)]
    p = 0.02
    err2 = diff[-1]
    status = None
    status = detect_new(err1, p, err2, u, s, n)
    code = control_measure(sip, dst_ip, str(dst_port), "S", "1000", n)
    if code != 0:
        logging.info('Control measure failed: {a}, {b}'.format(a=ip, b=dst_ip))
        status = 'undetectable'
    '''dataset['cu'].append(cu)
	dataset['asn'].append(asn)
	dataset['ip'].append(ip)
	dataset['cls'].append(cls)
	dataset['dst_ip'].append(dst_ip)
	#dataset['td'].append(td)
	dataset['status'].append(status)'''
    ofile.write(cu+','+asn+','+ip+','+cls+','+dst_ip+','+status+'\n')
    logging.info('{a} | {b} | {c} | {d}'.format(
        a=ip, b=dst_ip, c=actual, d=predictions))
    return code, dst_ip


def single_censor_measure(ip, protocol, port, ns, dst_ip, dst_port, plth, spoof, dataset, cu):
    code = 0
    count = 0
    for i in range(3):
        ipid = probe(ip, protocol, 'SA', port, ns)
        if ipid == -1:
            count = count+1
        time.sleep(1)
    if count == 3:
        logging.info('Client unreachable: {a}'.format(a=ip))
        code = 1
        return code, dst_ip

    res = predict_ipids(ip, protocol, 'SA', port, ns, 1, 10)  # fs = 1, sl = 10
    if res != 1:
        logging.info('Not applicable: {a}, {res}'.format(a=ip, res=res))
        code = 1
        return code, dst_ip

    #astatus = test_dst_port(dst_ip, protocol, 'S', dst_port, ns)
    td = compute_td(dst_ip, dst_port)
    print(td)
    if td <= 0:
        logging.info('Web server unreachable: {a}'.format(a=dst_ip))
        code = 1
        return code, dst_ip

    sliding_window = list()
    pr = 1
    wlth = 5
    plth = plth
    mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
    emax = 0.0
    p2 = 0.02
    flag = 'test'
    ipids = list()
    actual = list()
    predictions = list()
    chps_ind = list()
    outlier_ind = list()
    tem_actual = list()
    while True:
        ipid = probe(ip, protocol, 'SA', port, ns)
        start = time.monotonic()
        ipids.append(ipid)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        tem_actual.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(ipid)
            sliding_window.pop(0)
        if len(predictions) == plth-1:
            diff = eliminate_trans_error(chps_ind, actual, predictions)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)

            if len(after_diff) < (plth-1) * 0.7:
                logging.info('Invalid: {a}, {b}'.format(a=ip, b=actual))
                code = 1
                return code, dst_ip
            mae = np.mean(abs(array(after_diff)))
            smape = sMAPE02(chps_ind, actual, predictions)
            n, u, s, emax = spoofing_samples(after_diff)
            #print('n, p2: ', n, p2)
            # f.write(ip+','+str(smape)+','+str(n)+'\n')
            if n > 10:
                logging.info('n>10, require retest: {a}'.format(a=ip))  # 10
                code = 1
                return code, dst_ip
            if spoof:
                spoofing_probe(ip, protocol, port, ns, dst_ip,
                               dst_port, n, flag)  # port should be random
                # spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.5:
                predictions.append(math.nan)
                time.sleep(pr)
                continue
            times = list()
            for i in range(len(sliding_window)):
                times.append(i)
            tHistory = times
            MAX = 65536

            outlier = True
            if len(predictions) >= plth:
                outlier = False

            if containNAN(sliding_window):
                vel = computeIpidVelocityNan(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact

            if vel < 1000:
                thr = 15000  # experimentially specify the threshold
            else:
                thr = 30000
            if vel > 10000:
                outlier = False  # For high fluctuating

            # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
            if len(predictions) > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                chps_ind.append(i-2)
                chps_ind.append(i-1)

            if len(predictions) == plth+td:
                break

            sliding_window = fill_miss_values(sliding_window)

            sliding_window, _ = filter_outliersv2(
                outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)

            gp_one_time_forecast(sliding_window, predictions, MAX)
            '''wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)'''
            if predictions[-1] < 0:
                predictions[-1] = 0

        #lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
        time.sleep(pr)
        #end = time.monotonic()
        #elapsed = end-start
        # print(elapsed)
    diff = eliminate_trans_error(chps_ind, actual, predictions)
    if math.isnan(diff[-1]) or math.isnan(diff[-4]):
        logging.info('Packet loss: {a}'.format(a=ip))
        code = 1
        return code, dst_ip
    # here design a test: no error, manually subtract n to the predcition errors
    err1 = diff[-(td+1)]
    p = 0.02
    err2 = diff[-1]
    status = None
    status = detect_new(err1, p, err2, u, s, n)

    dataset['cu'].append(cu)
    dataset['ip'].append(ip)
    dataset['mae'].append(mae)
    dataset['smape'].append(smape)
    dataset['n'].append(n)
    dataset['dst_ip'].append(dst_ip)
    dataset['td'].append(td)
    dataset['status'].append(status)
    #print(ip, dst_ip, status, astatus)
    logging.info('{a} | {b} | {c} | {d}'.format(
        a=ip, b=dst_ip, c=actual, d=predictions))
    return code, dst_ip


def fill_miss_values(data):
    s = pd.Series(data)
    s = s.interpolate(method='pad')
    return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist()

def fill_predicted_values(data, predictions):
    if math.isnan(data[-1]) and len(predictions) > 0:
    	data[-1] = int(predictions[-1])
    return data
    
def count_asn():
    nets = list()
    with open('../censorship_measurement/clients_data/ipid_reflectors_All.asn.dat') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue
            asn = fields[1]
            if asn not in nets:
                nets.append(asn)
    print(nets)
    print(len(nets))


def extract_alexa_sites():
    f = open('../censorship_measurement/clients_data/test_list_alexa.dat', 'w')
    sites = list()
    with open('../censorship_measurement/clients_data/webserver_ips.dat') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 2:
                continue
            site = fields[0]
            print(site)
            if site in sites:
                continue
            f.write(site+'\n')
            sites.append(site)
            if len(sites) == 1000:
                return
    f.close()


def compute_RTO():
    ips, ports = list(), list()
    with open('./ooni_ip_blocking_2022_final.csv') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 6:
                continue
            ip = fields[4]
            port = fields[5].strip('\n')
            ips.append(ip)
            ports.append(int(port))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip, port in zip(ips, ports):
            futures.append(executor.submit(compute_td, ip, port))
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            print(res)


def filter_unreachable_webservers():
    f = open('./test_list_final.dat', 'w')
    labels = list()
    urls = list()
    ips = list()
    ports = list()
    with open('./test_list.dat') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 4:
                continue
            label = fields[0]
            url = fields[1]
            dst_ip = fields[2]
            dst_port = fields[3].strip('\n')
            labels.append(label)
            urls.append(url)
            ips.append(dst_ip)
            ports.append(int(dst_port))

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for label, url, dst_ip, dst_port in zip(labels, urls, ips, ports):
            futures.append(executor.submit(test_dst_port, label,
                                           url, dst_ip, 'tcp', 'S', dst_port, ''))
        for future in concurrent.futures.as_completed(futures):
            res, label, url, dst_ip, dst_port = future.result()
            if res == 'open':
                f.write(label+','+url+','+dst_ip+','+str(dst_port)+'\n')
    f.close()


def test_reflectors():
    ips = list()
    cus = list()
    pfxs = list()
    domains = list()
    protocol = 'tcp'
    port = random.randrange(10000, 65535, 1)
    #port = 80
    dst_ip = '199.244.49.62'
    td = random.randrange(1, 2, 1)  # 1, 2, 3, 4
    dst_port = 80
    l = 30
    spoof = False
    dataset = {
        'cu': [],
        'pfx': [],
        'ip': [],
        'mae': [],
        'smape': [],
        'n': [],
        'dst_ip': [],
        'status': [],
    }

    # ./lr.reflectors.(low).res, scan_target_reflectors.res
    with open('./ipid_reflectors_EU.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 3:
                continue
            domain = ''
            cu = fields[0]
            pfx = fields[1]
            ip = fields[2].strip('\n')
            domains.append(domain)
            ips.append(ip)
            cus.append(cu)
            pfxs.append(pfx)
            if len(ips) == 300:  # 10
                with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
                    futures = []
                    for ip, cu, pfx, ns in zip(ips, cus, pfxs, domains):
                        futures.append(executor.submit(controlled_experiment, ip, protocol,
                                                       port, cu, pfx, ns, dst_ip, dst_port, td, l, spoof, dataset))
                    for future in concurrent.futures.as_completed(futures):
                        # print('Done!')
                        continue
                ips = list()
                cus = list()
                pfxs = list()
                domains = list()

        with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
            futures = []
            for ip, cu, pfx, ns in zip(ips, cus, pfxs, domains):
                futures.append(executor.submit(controlled_experiment, ip, protocol,
                                               port, cu, pfx, ns, dst_ip, dst_port, td, l, spoof, dataset))
            for future in concurrent.futures.as_completed(futures):
                print('Done!')

    #df = pd.DataFrame(dataset)
    #df.to_csv('./ipid_reflectors_RU_refine.dat', index=False)


def test_reflectors_analysis():
    f = open(
        '../censorship_measurement/clients_data/ipid_reflectors_All.refine02.dat', 'w')
    ips = list()
    #mips = list()
    with open('../censorship_measurement/clients_data/ipid_reflectors_All.filter01.new.dat') as filehandle:
        filecontents = filehandle.readlines()
        n = len(filecontents)
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(",")
            if len(fields) < 4:
                continue
            ip = fields[2]
            ips.append(ip)
            # if ip not in mips:
            #	mips.append(ip)
    print(len(ips))
    merged_ips = list()
    with open('../censorship_measurement/clients_data/ipid_reflectors_All.filter02.new.dat') as filehandle:
        filecontents = filehandle.readlines()
        n = len(filecontents)
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(",")
            if len(fields) < 4:
                continue
            ip = fields[2]
            # if ip not in mips:
            #	mips.append(ip)
            if ip not in ips:
                continue
            merged_ips.append(ip)
    print(len(merged_ips))
    ips = list()
    #final_ips = list()
    with open('../censorship_measurement/clients_data/ipid_reflectors_All.filter03.new.dat') as filehandle:
        filecontents = filehandle.readlines()
        n = len(filecontents)
        for i, line in enumerate(filecontents):
            if i == 0:
                continue
            fields = line.split(",")
            if len(fields) < 4:
                continue
            ip = fields[2]
            # if ip not in mips:
            #	mips.append(ip)
            if ip not in merged_ips:
                continue
            f.write(line)
            # final_ips.append(ip)
    f.close()


def compute_tds(services):
    tds = list()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for service in services:
            fields = service.split(':')
            dst_ip = fields[0]
            dst_port = int(fields[1])
            futures.append(executor.submit(compute_td, dst_ip, dst_port))
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            tds.append(res)
    return tds


def test_webservers():
    webservers = list()
    dst_ports = list()
    with open('./test_list_global_final.dat', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 4:
                continue
            dst_ip = fields[2]
            dst_port = fields[3].strip('\n')
            dst_ports.append(dst_port)
            webservers.append(dst_ip)
    ip = '94.183.134.37'
    protocol = 'tcp'
    port = random.randrange(10000, 65535, 1)
    ns = ''
    dataset = {
        'ip': [],
        'mae': [],
        'smape': [],
        'n': [],
        'dst_ip': [],
        'status': [],
        'astatus': [],
    }

    for dst_ip, dst_port in zip(webservers, dst_ports):
        td = 1
        our_ip = '199.244.49.62'
        our_port = 80
        controlled_experiment(ip, protocol, port, ns,
                              our_ip, our_port, td, 30, True, dataset)
        td = compute_td(dst_ip, dst_port)
        single_censor_measure(ip, protocol, port, ns,
                              dst_ip, dst_port, td, 30, True, dataset)

    df = pd.DataFrame(dataset)
    df.to_csv('./test_ooni_IR_webservers_block.res', index=False)


lib = cdll.LoadLibrary("./ipid_pred_lib.so")
logging.basicConfig(level=logging.INFO, filename='./test_reflectors_new.log')

def main():
    test_webservers()


if __name__ == "__main__":
    # execute only if run as a script
    main()
