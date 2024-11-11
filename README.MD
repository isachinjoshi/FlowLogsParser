Assumptions
===========

1. Flow Logs file (flow_logs.csv) won't have any headers as mentioned in the sample input

2. Look up table file (look_up_table.csv) will have headers

3. If any of the input file is missing, program would terminate with run time error 'No such file or directory'

4. With each run, the output files are overwritten

5. Didn't find any significant difference between flow log version 1 and 2; version 2 has just some additional fields


How to Run the Code
===================

1. With editors: open with Editors (like VSCode) and click the run button

2. With terminal: python <path_to>main.py

Tests Executed
==============

1. Tested with few entries in flow logs file and look up table file
2. Tested with flow log file of size over 10 MB
3. Tested with look up table file with 10K entries
4. Tested with malformed/incorrect look up table entry(ies) 