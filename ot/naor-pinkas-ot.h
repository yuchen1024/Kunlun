#include "../crypto/ec_point.hpp"

/*
 * Noar Pinkas OT
 * [REF] Implementation of "Efficient Oblivious Transfer Protocols"
 * https://dl.acm.org/doi/10.5555/365411.365502
 */


void send(const block* data0, const block* data1, int length)
{
	std::vector<BigInt> vec_r(length);
	std::vector<ECPoint> vec_pk0(length);
	std::vector<ECPoint> vec_k0(length);
	std::vector<ECPoint> vec_k1(length); 
	std::vector<ECPoint> vec_gr(length); 
	std::vector<ECPoint> vec_Cr(length); 

	// offline process
	// compute C = g^d
	BigInt d = GetRandomBnLessThan(order);
	ECPoint C = generator * d;

	//  compute g^r[i] and C^r[i]
	for(auto i = 0; i < length; i++) {
		vec_r[i] = GetRandomBnLessThan(order);
		vec_gr[i] = g * vec_r[i];
		vec_Cr[i] = C * vec_r[i];
	}

	// send C
	io->send_pt(&C);
	io->flush();

	// send g^r[i]
	for(auto i = 0; i < length; i++) {
		io->send_pt(&vec_gr[i]);
	}
	io->flush();


	// receive pk0[i]
	for(auto i = 0; i < length; i++) {
		io->recv_pt(G, &vec_pk0[i]);
	}

	// send m0 and m1
	block m[2];
	for(auto i = 0 ; i < length; ++i) {
		vec_k0[i] = pk0[i] * vec_r[i];
		vec_k1[i] = vec_Cr[i] - vec_k0[1];
		m[0] = Hash::KDF(vec_k0[i]) ^ data0[i];
		m[1] = Hash::KDF(vec_k1[i]) ^ data1[i];
		io->send_data(m, 2*sizeof(block));
	}

}

void recv(block* data, const bool* b, int length)
{
	std::vector<BigInt> vec_sk(length);
	std::vector<ECPoint> vec_gr(length); 
		Point pk[2];
		block m[2];
		Point C;
	for(auto i = 0; i < length; ++i){
		vec_sk[i] = GetRandomBnLessThan(order);
	}
	
	ECPoint C; 	
	io->recv_pt(&C);
	io->flush();

	// send pk0[i]
	for(auto i = 0; i< length; i++) {
		if(b[i] == 1){
			pk0 = C - g * vec_sk[i]; 
		} else {
			pk0 = g * vec_sk[i];
		}
		io->send_pt(&pk0);
	}

	// compute Kb[i]
	for(auto i = 0; i < length; i++) {
		io->recv_pt(&gr[i]);
		vec_kb[i] = gr[i]* vec_sk[i];
	}
	io->flush();
	
	// decrypt with Kb[i]
	for(auto i = 0; i < length; i++) {
		int selection_bit = b[i] ? 1 : 0;
		io->recv_data(m, 2*sizeof(block));
		data[i] = m[selection_bit] ^ Hash::KDF(vec_kb[i]);
	}
}
#endif
