from socket import htons,htonl
import os

rules_raw = []

ipproto_id = {'ICMP':1,'IGMP':2,'TCP':6,'UDP':17,0:0}
action_id = {'DROP':1,'REDIRECT':4,0:0}

'''
0-ipproto
1-saddr
2-daddr
3-sport
4-dport
5-action
'''

def read_rule_from_txt():
    current_file_dir = os.path.dirname(__file__)
    rule_file = open("%s/rules.txt"%current_file_dir)
    cnt = 0
    for rule in rule_file.readlines():
        r = rule.split()
        if len(r) == 6:
            rules_raw.append([r[0],int(r[1]),int(r[2]),int(r[3]),int(r[4]),r[5]])
            cnt += 1
            print("added rule %d:%s"%(cnt,rule))
        else:
            print("error occured when process rule:%s"%rule)


def rule_pretreat(rules_raw):
    read_rule_from_txt()
    rules = []
    for r in rules_raw:
        rules.append([ipproto_id[r[0]],htonl(r[1]),htonl(r[2]),htons(r[3]),htons(r[4]),action_id[r[5]]])
    return rules
    

