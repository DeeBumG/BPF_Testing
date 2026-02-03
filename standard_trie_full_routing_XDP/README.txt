redirect_to_f1.py and redirect_to_f0.py currently work

redirect_to_f1 receives packets on f1 and sends them back out on f1
redirect_to_f0 receives packets on f1 and sends them out f0

any other random traffic is also sent out the respective interface

run "sudo python3 <program>.py" - it will take about 20 secs to load routes, then run trex
