# Naor-Pinkas Oblivious Transform
`NPOT` is an implementation of [Efficient Oblivious Transfer Protocols](https://dl.acm.org/doi/10.5555/365411.365502). It also plays the role as base OT in [`IKNPOTE`](./iknp_ote.md). 1-out-of-2 OT is a two-party protocol, where sender takes as input two strings $\{m_0, m_1\}$, and receiver takes as input a random bit $b$ and obtains nothing other than $m_b$ while sender learns nothing about $b$.


## Construction
All identifiers are defined in namespace `NPOT`.

### Public Parameters
```
struct PP
{
    ECPoint g;
};
```
The `PP` struct holds the public parameter of NPOT protocol, which is a generator group `g`. It can be initialized by `Setup()`. 
```
PP Setup();
```


## Use
### Serialization
```
void SerializePP(PP &pp, std::ofstream &fout);
void SavePP(PP &pp, std::string pp_filename);
```
The struct `PP` can be serialized and saved to file named `pp_filename`. `SavePP` will call `SerializePP` internally.
```
void DeserializePP(PP &pp, std::ifstream &fin);
void FetchPP(PP &pp, std::string pp_filename);
```
Similarly, `FetchPP` will call `DeserializePP` to fetch serialized `PP` from file named `pp_filename`.

### Instantiate
If you want to instantiate a number of OTs, all you need to do is start two processes, one process act as sender and call `Send`, the other process act as receiver and call `Receive`.
```
void Send(NetIO &io, PP &pp, const std::vector<block>& vec_m0, const std::vector<block> &vec_m1, size_t LEN);
```
* `NetIO &io`: a class object handling communication through socket. Sender is deemed as "server".
* `PP &pp`: a public parameter struct of `NPOT`.
* `std::vector<block>& vec_m0`: a vector of messages. 
* `std::vector<block> &vec_m1`: another vector of messages.
* `size_t LEN`: the number of OT instances, that is, the length of vector `vec_m0` and `vec_m1`.

```
std::vector<block> Receive(NetIO &io, PP &pp, const std::vector<uint8_t> &vec_selection_bit, size_t LEN);
```
* `NetIO &io`: a class object handling communication through socket. Receiver is deemed as "client".
* `PP &pp`: a public parameter struct of `NPOT`.
* `std::vector<uint8_t> &vec_selection_bit`: a vector of choice bits. Receiver will choose from `vec_m0` or `vec_m1` according to its choice bits.
* `size_t LEN`: the number of OT instances, that is, the length of vector `vec_selection_bit`. The caller must guarantee that it is the same as input `size_t LEN` of `Send`.

The messages receiver chooses is returned from `Receive` in `std::vector<block>` proto.


## Sample Code
An example of how to instantiate 128 OTs. More detailed sample code is provided in test files. 
```
PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed
NPOT::PP pp = NPOT::Setup(); 
size_t NUM = 128; // set instance size

std::vector<uint8_t> vec_selection_bit = GenRandomBits(seed, NUM); 
std::vector<block> vec_K0 = PRG::GenRandomBlocks(seed, NUM);
std::vector<block> vec_K1 = PRG::GenRandomBlocks(seed, NUM);

if (party == "sender")
{
    NetIO sender_io("server", "", 8080); 
    NPOT::Send(sender_io, pp, vec_K0, vec_K1, NUM); 
}

if (party == "receiver")
{
    NetIO receiver_io("client", "127.0.0.1", 8080);
    std::vector<block> vec_K = NPOT::Receive(receiver_io, pp, vec_selection_bit, NUM); 
}
```