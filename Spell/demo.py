#!/usr/bin/env python

import sys
sys.path.append('../../')
from Spell import LogParser

input_dir  = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Spell'  # The input directory of log file
output_dir = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Spell'  # The output directory of parsing results
log_file   = r'C:/Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\logparser\logparser\Spell\swat_attack_spell.log'  # The input log file name
#log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'  # HDFS log format
log_format = '<Content>'
tau        = 0.5  # Message type threshold (default: 0.5)
regex      = []  # Regular expression list for optional preprocessing (default: [])

parser = LogParser(indir=input_dir, outdir=output_dir, log_format=log_format, tau=tau, rex=regex)
parser.parse(log_file)
