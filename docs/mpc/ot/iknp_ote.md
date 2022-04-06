# IKNP OT Extension
`IKNPOTE` is an implementation of [Extending oblivious transfers efficiently](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf). It uses a small number of base OTs (implementing by [`NPOT`](./naor_pinkas_ot.md)) with SKE to generate a lot number of 1-out-of-2 OTs.


## Construction
All identifiers are defined in namespace `IKNPOTE`.

### Public Parameters
```
struct PP
{
    uint8_t malicious = 0; // false
    NPOT::PP baseOT;   
};
```
* `uint8_t malicious`: an indication variable, indicating if the protocol is secure against semi-honest adversaries(`malicious = 0`) or malicious adversaries(`malicious = 1`).
* `NPOT::PP baseOT`: a struct at namespace [`NPOT`](./naor_pinkas_ot.md), which depicts the public parameters of NPOT protocol.

`PP` can be initialized by `Setup()`. 
```
PP Setup()
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
#### Common Case
This situation happens when you want to obtain a vast amount of base OT instances efficiently. The interface is the same as what we have in [`NPOT`](./naor_pinkas_ot.md). Sender will call `Send`, receiver will call `Receive` and output a vector of messages.
```
void Send(NetIO &io, PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t EXTEND_LEN); 
```
* `NetIO &io`: a class object handling communication through socket. Sender is deemed as "server".
* `PP &pp`: a public parameter struct of `IKNPOTE`.
* `std::vector<block>& vec_m0`: a vector of messages. 
* `std::vector<block> &vec_m1`: another vector of messages.
* `size_t EXTEND_LEN`: the number of OT instances, that is, the length of vector `vec_m0` and `vec_m1`. `EXTEND_LEN` can be very large, e.g. $2^{20}$. Note that there is a limit of `EXTEND_LEN` which has to satisfy `EXTEND_LEN % 128 = 0`. 

```
std::vector<block> Receive(NetIO &io, PP &pp, const std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN);
```
* `NetIO &io`: a class object handling communication through socket. Receiver is deemed as "client".
* `PP &pp`: a public parameter struct of `IKNPOTE`.
* `std::vector<uint8_t> &vec_selection_bit`: a vector of choice bits. Receiver will choose from `vec_m0` or `vec_m1` according to its choice bits.
* `size_t EXTEND_LEN`: the number of OT instances, that is, the length of vector `vec_selection_bit`. The caller must guarantee that it is the same as input `size_t EXTEND_LEN` of `Send`.

The messages receiver chooses is returned from `Receive` in `std::vector<block>` proto.

#### Onesided Case
Unlike the common case, there is a situation where sender has only one vector of messages, and receiver want to choose from sender's vector only when its choice bit is 1. For example, we have it used in [`PSO`](../pso/pso_from_mqrpmt.md) after getting an indication bit vector. 
```
void OnesidedSend(NetIO &io, PP &pp, std::vector<block> &vec_m, size_t EXTEND_LEN); 
```
* `NetIO &io`: a class object handling communication through socket. Sender is deemed as "server".
* `PP &pp`: a public parameter struct of `IKNPOTE`.
* `std::vector<block>& vec_m`: a vector of messages. 
* `size_t EXTEND_LEN`: the number of OT instances, that is, the length of vector `vec_m`. `EXTEND_LEN` can be very large, e.g. $2^20$. Note that there is a limit of `EXTEND_LEN` which has to satisfy `EXTEND_LEN % 128 = 0`. 

```
std::vector<block> OnesidedReceive(NetIO &io, PP &pp, const std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN);
```
* `NetIO &io`: a class object handling communication through socket. Receiver is deemed as "client".
* `PP &pp`: a public parameter struct of `IKNPOTE`.
* `std::vector<uint8_t> &vec_selection_bit`: a vector of choice bits. Receiver will choose from `vec_m` when its choice bit is 1.
* `size_t EXTEND_LEN`: the number of OT instances, that is, the length of vector `vec_selection_bit`. The caller must guarantee that it is the same as input `size_t EXTEND_LEN` of `Send`.

The messages receiver chooses is returned from `Receive` in `std::vector<block>` proto.


## Sample Code
An example of how to instantiate $2^{20}$ OTs. More detailed sample code is provided in test files.
```
PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed
IKNPOTE::PP pp = IKNPOTE::Setup(); 
size_t EXTEND_LEN  = 1 << 20; // set instance size

std::vector<uint8_t> vec_selection_bit = GenRandomBits(seed, EXTEND_LEN); 
std::vector<block> vec_K0 = PRG::GenRandomBlocks(seed, EXTEND_LEN);
std::vector<block> vec_K1 = PRG::GenRandomBlocks(seed, EXTEND_LEN);

if (party == "sender")
{
    NetIO sender_io("server", "", 8080); 
    IKNPOTE::Send(sender_io, pp, vec_K0, vec_K1, EXTEND_LEN); 
}

if (party == "receiver")
{
    NetIO receiver_io("client", "127.0.0.1", 8080);
    std::vector<block> vec_K = IKNPOTE::Receive(receiver_io, pp, vec_selection_bit, EXTEND_LEN); 
}
```