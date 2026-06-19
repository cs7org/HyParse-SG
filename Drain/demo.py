#!/usr/bin/env python

import sys
sys.path.append('../../')
from Drain import LogParser

input_dir  = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Drain' # The input directory of log file
output_dir = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Drain\demo_result'  # The output directory of parsing results
log_file   = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Drain\dnp3_balanced_drain.log'  # The input log file name
#log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>' # HDFS log format
log_format = '<Content>'
# Regular expression list for optional preprocessing (default: [])
regex      = [
    r'blk_(|-)[0-9]+' , # block id
    r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)', # IP
    r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$', # Numbers
]
st         = 0.5  # Similarity threshold
depth      = 4  # Depth of all leaf nodes

parser = LogParser(log_format, indir=input_dir, outdir=output_dir,  depth=depth, st=st, rex=regex)
parser.parse(log_file)
