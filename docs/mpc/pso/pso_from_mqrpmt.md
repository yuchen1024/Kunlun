# Private Set Operation From mqRPMT
`PSO` implements private set intersection (PSI), private set union (PSU), private set intersection cardinality (PSI-card) and private set intersection cardinality and sum (PSI-card-sum) based on [`cwPRFmqRPMT`](../rpmt/cwprf_mqrpmt.md) 
and [`ALSZOTE`](../ot/iknp_ote.md).

* PSI allows two parties, the sender and the receiver, to compute the intersection of their private sets without revealing extra information to each other.
    - In the PSI-card setting, instead of getting the contents of the intersection, the receiver will get the cardinality.
    - In the PSI-card-sum setting, the receiver additionally holds a value per each item in its set, in the end, 
    the receiver obtains intersection cardinality and sum, and the sender obtains the intersection cardinality. 
* PSU allows two parties, the sender and the receiver, to compute the union of their private sets without revealing extra information to each other.


## Construction
All identifiers are defined in namespace `PSO`.

### Public Parameters
```
struct PP
{
    IKNPOTE::PP ote_part; 
    cwPRFmqRPMT::PP mqrpmt_part; 
};
```
* `ALSZOTE::PP ote_part`: a struct at namespace [`ALSZOTE`](../ot/iknp_ote.md), which depicts the public parameters of ALSZ OT extension protocol.
* `cwPRFmqRPMT::PP mqrpmt_part`: a struct at namespace [`cwPRFmqRPMT`](../rpmt/cwprf_mqrpmt.md), which depicts the public parameters of multi-point RPMT protocol.

`PP` can be initialized by `Setup`. The input `lambda` is statistical security parameter.
```
PP Setup(std::string filter_type, size_t lambda);
```


## Use
### Serialization
```
void SavePP(PP &pp, std::string pp_filename);
```
The struct `PP` can be serialized and saved to file `pp_filename`.
```
void FetchPP(PP &pp, std::string pp_filename);
```
Similarly, `FetchPP` is designed to fetch serialized `PP` from file `pp_filename`.

### PSI
```
std::vector<block> PSIServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN);
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_X`: a vector of items in server's set.
* `size_t LEN`: the length of vector `vec_X`.

The intersection of `vec_X` and `vec_Y` is returned from `PSIServer` in `std::vector<block>` proto.

```
void PSIClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN);
``` 
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_Y`: a vector of items in client's set.
* `size_t LEN`: the length of vector `vec_Y`, which should be the same as `vec_X`'s length.

### PSI-card
```
size_t PSIcardServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN)
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_X`: a vector of items in server's set.
* `size_t LEN`: the length of vector `vec_X`.

The intersection cardinality is returned from `PSIcardServer`.

```
void PSIcardClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_Y`: a vector of items in client's set.
* `size_t LEN`: the length of vector `vec_Y`, which should be the same as `vec_X`'s length.

### PSI-card-sum
```
int64_t PSIcardsumSend(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_X`: a vector of items in server's set.
* `size_t LEN`: the length of vector `vec_X`.

The the sum of the labels in the intersection is returned from `PSIsumServer`.

```
void PSIcardsum::Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y, std::vector<int64_t> &vec_label, size_t LEN) 
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_Y`: a vector of items in client's set.
* `std::vector<int64_t> &vec_label`: a vector of labels of client's items.
* `size_t LEN`: the length of vector `vec_Y`, which should be the same as `vec_X`'s length.

### PSU
```
std::vector<block> PSU::Send(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_X`: a vector of items in server's set.
* `size_t LEN`: the length of vector `vec_X`.

The union of `vec_X` and `vec_Y` is returned from `PSUServer` in `std::vector<block>` proto.

```
void PSU::Receiver(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
```
* `NetIO &io`: a class object handling communication through socket.
* `PP &pp`: a public parameter struct of `PSO`.
* `std::vector<block> &vec_Y`: a vector of items in client's set.
* `size_t LEN`: the length of vector `vec_Y`, which should be the same as `vec_X`'s length.


## Sample Code
An example of how to implement PSI-Sum. More detailed sample code is provided in test files.
```
PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed
PSO::PP pp = PSO::Setup("bloom", 40);
size_t LEN  = 1 << 20; // set set size

std::vector<block> vec_X = PRG::GenRandomBlocks(seed, LEN);
std::vector<block> vec_Y = PRG::GenRandomBlocks(seed, LEN);
std::vector<int64_t> vec_label = GenRandomIntegerVectorLessThan(LEN, 100);

if(current == PSI_sum){
    if(party == "server"){
        NetIO server_io("server", "", 8080);
        int64_t SUM = PSO::PSIsumServer(server_io, pp, vec_X, LEN);
    }
    
    if(party == "client"){
        NetIO client_io("client", "127.0.0.1", 8080);        
        PSO::PSIsumClient(client_io, pp, vec_Y, vec_label, LEN);
    } 
}
```
