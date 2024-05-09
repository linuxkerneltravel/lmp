#!/bin/bash

set -ex

origin_name=$1
upper_name=${origin_name^^}
array=(${origin_name//_/ })
name=""
for var in ${array[@]}
do
   name=$name${var^}
done
class_name=$name"StackCollector"


cp include/bpf_wapper/template.h include/bpf_wapper/$origin_name.h
sed -i 's/_TEMPLATE_H__/_SA_'$upper_name'_H__/g' include/bpf_wapper/$origin_name.h
sed -i 's/TemplateClass/'$class_name'/g' include/bpf_wapper/$origin_name.h
sed -i 's/template/'$origin_name'/g' include/bpf_wapper/$origin_name.h

cp src/bpf_wapper/template.cpp src/bpf_wapper/$origin_name.cpp
sed -i 's/TemplateClass/'$class_name'/g' src/bpf_wapper/$origin_name.cpp
sed -i 's/template/'$origin_name'/g' src/bpf_wapper/$origin_name.cpp

cp bpf/template.bpf.c bpf/$origin_name.bpf.c
sed -i 's/template/'$origin_name'/g' bpf/$origin_name.bpf.c

sed -i '/#include "bpf_wapper\/on_cpu.h"/a#include "bpf_wapper\/'$origin_name'.h"' src/main.cpp

sed -i '/auto MainOption = _GREEN "Some overall options" _RE %/iauto '$name'Option = clipp::option("'$origin_name'").call([]{ StackCollectorList.push_back(new '$class_name'()); }) % COLLECTOR_INFO("'$origin_name'");' src/main.cpp

sed -i '/MainOption,/i'$name'Option,' src/main.cpp