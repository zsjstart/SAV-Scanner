# SAVscan
We develop a practical tool based on the predictive analysis of global IPID (IP Identification) counters to infer the implementation techniques for SAV. This tool enables the first empirical analysis of SAV implementation strategies across ASes, with a specific focus on two techniques: ACLs and uRPF.
We first identify the presence of destination-side SAV at the ingress of the tested networks. Once the SAV presence is determined, we proceed to verify whether it is implemented through ACLs or uRPF. The differentiation between the two techniques relies on AS topologies and AS relationships.

