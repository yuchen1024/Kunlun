# Multi-Point RPMT
`cwPRFmqRPMT` implements multi-point RPMT based on weak commutative PSU, which is designed to be used in [`PSO`](../pso/pso_from_mqrpmt.md). The functionality of multi-point RPMT can be described as server with input set $X$ and client with input set $Y$, in the end, server learns an indication bit vector indicating which items of client's set $Y$ are in its set $X$, while client gets nothing. 


## Construction
All identifiers are defined in namespace `cwPRFmqRPMT`.

### Define

* BLOOMFILTER means we will use bloom filter, else use permutation.

### Public Parameters
```
struct PP
{
    bool malicious = false;
    std::string filter_type; // shuffle, bloom
    size_t statistical_security_parameter;
};
```

* `size_t statistical_security_parameter`: used to specify the false positive probability of bloom filter, which equals `1/(1 << {statistical_security_parameter/2})`.

`PP` can be initialized by `Setup`. The input `lambda` is statistical security parameter.
```
PP Setup(size_t lambda);
```


## Use
### Serialization
```
void SerializePP(PP &pp, std::ofstream &fout);
void SavePP(PP &pp, std::string pp_filename);
```
The struct `PP` can be serialized and saved to file `pp_filename`. `SavePP` will call `SerializePP` internally.
```
void DeserializePP(PP &pp, std::ifstream &fin);
void FetchPP(PP &pp, std::string pp_filename);
```
Similarly, `FetchPP` will call `DeserializePP` to fetch serialized `PP` from file `pp_filename`.

### Instantiate
Start two processes, one process act as server and call `Server`, the other process act as client and call `Client`.
```
std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN);
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `cwPRFmqRPMT`.
* `std::vector<block> &vec_X`: a vector of items in server's set.
* `size_t LEN`: the length of vector `vec_X`.

The indication bit vector server obtains is returned from `Server` in `std::vector<uint8_t>` proto.

```
void Client(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN);
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `cwPRFmqRPMT`.
* `std::vector<block> &vec_Y`: a vector of items in client's set.
* `size_t LEN`: the length of vector `vec_Y`, which should be the same as `vec_X`'s length.


## Sample Code
An example of how to instantiate multi-point RPMT. More detailed sample code is provided in test files. 
```
PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed
cwPRFmqRPMT::PP pp = cwPRFmqRPMT::Setup("bloom", 40);
size_t LEN  = 1 << 18; // set set size

std::vector<block> vec_X = PRG::GenRandomBlocks(seed, LEN);
std::vector<block> vec_Y = PRG::GenRandomBlocks(seed, LEN);

if (party == "server")
{
    NetIO server("server", "", 8080);
    std::vector<uint8_t> vec_indication_bit_real = cwPRFmqRPMT::Server(server, pp, vec_X, LEN);
}

if (party == "client")
{
    NetIO client("client", "127.0.0.1", 8080);        
    cwPRFmqRPMT::Client(client, pp, vec_Y, LEN); 
}
```
