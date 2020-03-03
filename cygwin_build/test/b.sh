#!/bin/sh
echo this is b 
$(dirname $0)/c.sh & $(dirname $0)/d.sh
