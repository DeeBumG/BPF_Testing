redirect_to_f0_batch.py 
-XDP program with internal FIB that redirects packets from f1 to f0
-Uses a batching approach to load all routes into the trie at once, allowing fast FIB setup of 900000+ routes

redirect_to_f0_timing
-same as above, with added timing overhead (slightly slower but with timing output for each lookup)

test.py
-testing program used during poptrie kernel development (does not use full BGP table)