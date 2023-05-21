### StarkEx playground

#### Usage
1. Install `docker`:
```
apt install -y docker.io
```
2. Build the docker image:
```
docker build -t <MEMORABLE_NAME> .
```
3. Run the docker:
```
docker run -it <MEMORABLE_NAME>
```
4. In the docker container, run `./player.py --help` for further instructions.

#### Examples for querying the feeder gateway

To print the last batch ID to console, run:
```
wget -nv -q -O- https://gw.playground-v2.starkex.co/feeder_gateway/get_last_batch_id
```

Given the batch ID (say, batch ID 23), fetch the batch info by running:
```
wget -nv -q -O- https://gw.playground-v2.starkex.co/feeder_gateway/get_batch_info?batch_id=23
```
