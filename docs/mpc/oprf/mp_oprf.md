# Multi-Point OPRF
This is an implementation of multi-point OPRF in [Private Set Intersection in the Internet Setting From Lightweight](https://eprint.iacr.org/2020/729).

## Construction
All identifiers are defined in namespace `MPOPRF`.

### Public Parameters
```
struct PP
{
    size_t set_size; // n
    size_t matrix_height; // m
    size_t log_matrix_height; // logm
    size_t matrix_width; // w
    size_t H2_OUTPUT_LEN; // \ell2 in bytes
    size_t BATCH_SIZE;

    NPOT::PP npot_part;
    PRG::Seed commonseed; 
};
```

* `size_t set_size`: the set size of receiver's input set.
* `size_t matrix_height`: the height of the OPRF key matrix, `matrix_height = set_size`.
* `size_t log_matrix_height`: the log height of the OPRF key matrix.
* `size_t matrix_width`: the width of the OPRF key matrix.
* `size_t H2_OUTPUT_LEN`: the output length $l_2$ in bytes of hash function H2, `H2_OUTPUT_LEN = ((sigma + 2*log_set_size) + 7) >> 3` (page 14  section 3.3).
* `size_t BATCH_SIZE`: the batch size dealing with the `set_size` loops, it should satisfy the limit of `set_size % BATCH_SIZE = 0`.
* `NPOT::PP npot_part`: the public parameter struct of [`NPOT`](../ot/naor_pinkas_ot.md).
* `PRG::Seed commonseed`: a common PRG seed, used to generate a number of AES keys, $PRG(commonseed) \rightarrow k_0 || k_1 || \cdots || k_t$. 

`PP` can be initialized by `Setup`.
```
PP Setup(size_t log_set_size, size_t sigma = 40);
```

* `size_t log_set_size`: the log set size of receiver's input set.
* `size_t sigma`: the statistical security parameter, default to 40 if unset.

## Use

```
std::vector<std::vector<uint8_t>> Send(NetIO &io, PP &pp);
```
* `NetIO &io`: a class object handling communication through socket. Sender is deemed as "server".
* `PP &pp`: the public parameter struct of `MPOPRF`.

The OPRF key sender obtains is returned from `Send` in `std::vector<std::vector<uint8_t>>` proto.

```
std::vector<std::string> GetOPRFValues(PP &pp, std::vector<std::vector<uint8_t>> &oprfkey, std::vector<block> &vec_X);
```
* `PP &pp`: the public parameter struct of `MPOPRF`.
* `std::vector<std::vector<uint8_t>> &oprfkey`: a matrix of OPRF key sender obtains.
* `std::vector<block> &vec_X`: a vector of items in sender's set.

The OPRF values sender evaluates is returned from `GetOPRFValues` in `std::vector<std::string>` proto. Each OPRF value is a `HASH_OUTPUT_LEN` bytes string.

```
std::vector<std::string> Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y);
```
* `NetIO &io`: a class object handling communication through socket. Receiver is deemed as "client".
* `PP &pp`: the public parameter struct of `MPOPRF`.
* `std::vector<block> &vec_X`: a vector of items in receiver's set.

The OPRF values receiver evaluates is returned from `Receive` in `std::vector<std::string>` proto. Each OPRF value is a `HASH_OUTPUT_LEN` bytes string.

## Sample Code
```
MPOPRF::PP pp = MPOPRF::Setup(log_set_size, salt); 
	
PRG::Seed seed = PRG::SetSeed(fix_key, 0);
std::vector<block> setX = PRG::GenRandomBlocks(seed, 1 << log_set_size);
std::vector<block> setY = PRG::GenRandomBlocks(seed, 1 << log_set_size);

if (party == "sender")
{
    NetIO server("server", "", 8080);
    std::vector<std::vector<uint8_t>> oprfkey = MPOPRF::Send(server, pp);
    sender_oprf_values = MPOPRF::GetOPRFValues(pp, oprfkey, setX);
}
    
if (party == "receiver")
{
    NetIO client("client", "127.0.0.1", 8080);
    receiver_oprf_values = MPOPRF::Receive(client, pp, setY);
}
```