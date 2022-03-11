# Compiling Dataflow Queries for PISA Targets

In this discussion section we will compile the below query to P4:
```
# Threshold
Th = 10
Q = (PacketStream(qid=1)
     .filter(filter_keys=('tcp.flags',), func=('eq', 2))
     .map(keys=('ipv4.dstIP',), map_values=('count',), func=('eq', 1,))
     .reduce(keys=('ipv4.dstIP',), func=('sum',))
     .filter(filter_vals=('count',), func=('geq', Th))
     )
```
