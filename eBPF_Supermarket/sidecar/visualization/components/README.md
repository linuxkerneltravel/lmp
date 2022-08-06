# Visualization

To visualize the performance of pod with sidecar, we need to set up some toolchain components.

## Steps

For all machines, run commands following. 

Note that, if you want to deploy your components on different machines, you need to specify the following environment values. And, you can also edit the corresponding part of [Makefile](Makefile) to modify port configuration. 

```shell
export LOCAL_IP=$(YOUR_LOCAL_IP)
export SIDECAR_IP=$(YOUR_SIDECAR_NODE_IP)
export VISUALIZE_IP=$(YOUR_VISUALIZATION_NODE_IP)

make pull
make deploy
```

To stop all, just run:

```shell
make stop
make rm
```
