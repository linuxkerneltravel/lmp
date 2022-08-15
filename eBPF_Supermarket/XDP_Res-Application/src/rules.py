from socket import htons,htonl

rules_raw = []

ipproto_id = {'ICMP':1,'IGMP':2,'TCP':6,'UDP':17,0:0}
action_id = {'DROP':1,0:0}

'''
0-ipproto
1-saddr
2-daddr
3-sport
4-dport
5-action
'''

rules_raw.append(['ICMP',0,0,0,0,'DROP'])
rules_raw.append(['TCP',0,0,0,22,'DROP'])

def rule_pretreat(rules_raw):
    rules = []
    for r in rules_raw:
        rules.append([ipproto_id[r[0]],htonl(r[1]),htonl(r[2]),htons(r[3]),htons(r[4]),action_id[r[5]]])
    return rules
    

