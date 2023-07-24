from my_class import psid_t
from pyod.models.base import BaseDetector
from pyod.models.pca import PCA
from time import time


class adc:

    clf:BaseDetector
    mutant:dict
    res_prev:dict
    mutant_avg:float

    def __init__(self, clf=PCA()) -> None:
        self.clf = clf
        self.mutant = dict()
        self.res_prev = None
        self.mutant_avg = 0

    def do_label(self, count) -> list:
        start = time()
        self.clf.fit(count)
        print(self.clf.__module__, time() - start)
        return self.clf.labels_

    def auto_label(self, b) -> None:
        psids = [psid_t(psid) for psid in b["psid_count"].keys()]
        counts = [[i.value] for i in b["psid_count"].values()]
        labels = self.do_label(counts)
        self.mutant = {psid: label for psid, label in zip(
            psids, labels, strict=True)}

    def ad_log(self, b) -> None:
        mutant = self.mutant
        res_prev = self.res_prev
        psid_count = {psid_t(psid): n.value for psid,
                      n in b["psid_count"].items()}
        count = [[n] for n in psid_count.values()]
        try:
            labels = self.do_label(count)
        except:
            return
        res = {
            psid: label for psid, label
            in zip(psid_count.keys(), labels, strict=True)
        }
        for (psid, label), c in zip(res.items(), count):
            # if psid.ksid < 0 and psid.usid < 0:
            #     continue
            f = False
            n = mutant.setdefault(psid, 0)
            if res_prev and psid in res_prev.keys():
                if label > res_prev[psid]:
                    f = True
                    mutant[psid] = n+1
                else:
                    mutant[psid] = n-1
            elif label:
                f = True
                n = mutant.setdefault(psid, 0)
                mutant[psid] = n+1
            if f:
                print('pid:%6d\tsid:(%6d,%6d)\tcount:%-6d' %
                      (psid.pid, psid.ksid, psid.usid, c[0]))
        self.res_prev = res
        print('-'*32)

    def avg_mutant(self) -> None:
        ad_n = self.mutant.values()
        if len(ad_n):
            self.mutant_avg = sum(ad_n)/len(ad_n)
        else:
            self.mutant_avg = 0
        # for k, v in self.mutant.items():
        #     print(k, v)
        # print(ad_avg)

    def get_mutant(self, psid) -> int:
        if psid in self.mutant.keys():
            return 1 if self.mutant[psid] > self.mutant_avg else -1
        else:
            return 0

def rate(tgids: dict, rate_comm: callable):
    tp = fp = p = 0
    for tgd in tgids.values():
        for pd in tgd.values():
            if rate_comm(pd['name']):
                p += 1
            f = False
            for sd in pd['stacks'].values():
                if sd['label'] == 1:
                    print(pd['name'])
                    if rate_comm(pd['name']):
                        tp += 1
                    else:
                        fp += 1
                    f = True
                    break
            if f:
                break
    print("recall:%f%% precision:%f%%" %
          (tp/p*100 if p else 0, tp/(tp+fp)*100 if tp+fp else 0))
