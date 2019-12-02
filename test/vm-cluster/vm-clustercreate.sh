#!/bin/bash

name=temp
locs=(ukwest eastus)
loccount=${#locs[@]}

for (( i=0; i<$loccount; i++ ))
do
    loc=${locs[i]}
    let n=$i+1
    /bin/bash ./vmcreate.sh $name$n $loc
done