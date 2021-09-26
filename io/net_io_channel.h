#ifndef EMP_NETWORK_IO_CHANNEL
#define EMP_NETWORK_IO_CHANNEL

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "emp-tool/io/io_channel.h"
using std::string;


#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>



#ifndef EMP_IO_CHANNEL_H__
#define EMP_IO_CHANNEL_H__
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/prg.h"
#include "emp-tool/utils/group.h"
#include <memory>

namespace emp {
template<typename T> 
class IOChannel { public:
	uint64_t counter = 0;
	void send_data(const void * data, int nbyte) {
		counter +=nbyte;
		derived().send_data_internal(data, nbyte);
	}

	void recv_data(void * data, int nbyte) {
		derived().recv_data_internal(data, nbyte);
	}

	void send_block(const block* data, int nblock) {
		send_data(data, nblock*sizeof(block));
	}

	void recv_block(block* data, int nblock) {
		recv_data(data, nblock*sizeof(block));
	}

	void send_pt(Point *A, int num_pts = 1) {
		for(int i = 0; i < num_pts; ++i) {
			size_t len = A[i].size();
			A[i].group->resize_scratch(len);
			unsigned char * tmp = A[i].group->scratch;
			send_data(&len, 4);
			A[i].to_bin(tmp, len);
			send_data(tmp, len);
		}
	}

	void recv_pt(Group * g, Point *A, int num_pts = 1) {
		size_t len = 0;
		for(int i = 0; i < num_pts; ++i) {
			recv_data(&len, 4);
			g->resize_scratch(len);
			unsigned char * tmp = g->scratch;
			recv_data(tmp, len);
			A[i].from_bin(g, tmp, len);
		}
	}	

	void send_bool(bool * data, int length) {
		void * ptr = (void *)data;
		size_t space = length;
		const void * aligned = std::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
		if(aligned == nullptr)
			send_data(data, length);
		else{
			int diff = length - space;
			send_data(data, diff);
			send_bool_aligned((const bool*)aligned, length - diff);
		}
	}

	void recv_bool(bool * data, int length) {
		void * ptr = (void *)data;
		size_t space = length;
		void * aligned = std::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
		if(aligned == nullptr)
			recv_data(data, length);
		else{
			int diff = length - space;
			recv_data(data, diff);
			recv_bool_aligned((bool*)aligned, length - diff);
		}
	}


	void send_bool_aligned(const bool * data, int length) {
		unsigned long long * data64 = (unsigned long long * )data;
		int i = 0;
		for(; i < length/8; ++i) {
			unsigned long long mask = 0x0101010101010101ULL;
			unsigned long long tmp = 0;
#if defined(__BMI2__)
			tmp = _pext_u64(data64[i], mask);
#else
			// https://github.com/Forceflow/libmorton/issues/6
			for (unsigned long long bb = 1; mask != 0; bb += bb) {
				if (data64[i] & mask & -mask) { tmp |= bb; }
				mask &= (mask - 1);
			}
#endif
			send_data(&tmp, 1);
		}
		if (8*i != length)
			send_data(data + 8*i, length - 8*i);
	}
	void recv_bool_aligned(bool * data, int length) {
		unsigned long long * data64 = (unsigned long long *) data;
		int i = 0;
		for(; i < length/8; ++i) {
			unsigned long long mask = 0x0101010101010101ULL;
			unsigned long long tmp = 0;
			recv_data(&tmp, 1);
#if defined(__BMI2__)
			data64[i] = _pdep_u64(tmp, mask);
#else
			data64[i] = 0;
			for (unsigned long long bb = 1; mask != 0; bb += bb) {
				if (tmp & bb) {data64[i] |= mask & (-mask); }
				mask &= (mask - 1);
			}
#endif
		}
		if (8*i != length)
			recv_data(data + 8*i, length - 8*i);
	}


	private:
	T& derived() {
		return *static_cast<T*>(this);
	}
};
}
#endif



class NetIO{ 
	bool is_server;
	int mysocket = -1;
	int consocket = -1;
	FILE * stream = nullptr;
	char * buffer = nullptr;
	bool has_sent = false;
	string address;
	int port;

	NetIO(){
		set_nodelay();
		stream = fdopen(consocket, "wb+");
		buffer = new char[NETWORK_BUFFER_SIZE];
		memset(buffer, 0, NETWORK_BUFFER_SIZE);
		setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
		if(!quiet) std::cout << "connected\n";
	}

	void Setup_Server(); 
	void Setup_Client(); 


	~NetIO(){
		flush();
		fclose(stream);
		delete[] buffer;
	}

	void set_nodelay() {
		const int one = 1;
		setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
	}

	void set_delay() {
		const int zero = 0;
		setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&zero,sizeof(zero));
	}

	void flush() {
		fflush(stream);
	}

	void Send_Data_Internal(const void* data, size_t LEN); 
	void Receive_Data_Internal(void* data, size_t LEN);
};

// Server side socket programming
void NetIO::Setup_Server(const char* address, int port)
{
	this->port = port & 0xFFFF;
   	
	// create server master socket: socket descriptor is an integer (like a file-handle)
	int server_master_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	// set sockaddr_in with IP and port
	struct sockaddr_in server_address; 
	memset(&server_address, 0, sizeof(server_address)); // fill each byte with 0
	socklen_t server_address_size = sizeof(server_address);

	server_address.sin_family = AF_INET; // use IPV4
	server_address.sin_addr.s_addr = inet_addr(address); // set the server IP address
	//server.sin_addr.s_addr = htonl(INADDR_ANY); // set our address to any interface 
	server_address.sin_port = htons(port);           // set the server port number  

	// set the server master socket
	int reuse = 1;
	if (setsockopt(server_master_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse) < 0) {
		perror("error: setsockopt");
		exit(EXIT_FAILURE);
	}
	
	// bind the server master socket with IP and port
	if(bind(server_master_socket, (struct sockaddr *)&server_address, server_address) < 0) {
		perror("error: bind server master socket");
		exit(EXIT_FAILURE);
	}

	// begin to listen
	if(listen(server_master_socket, 1) < 0) {
		perror("error: listen server master socket");
		exit(EXIT_FAILURE);
	}

	// accept request from the client
	struct sockaddr_in client_address; // structure that holds ip and port
	socklen_t client_address_size = sizeof(client_address);
	int server_socket = accept(server_master_socket, (struct sockaddr*)&client_address, &client_address_size);
	if (server_socket < 0) {
		perror("error: accept");
		exit(EXIT_FAILURE);	
	}

	close(server_master_socket);
}

void NetIO::Setup_Client(const char* address, int port)
{
	this->port = port & 0xFFFF;

	// create client socket
	int client_socket = socket(AF_INET, SOCK_STREAM, 0);

	// set the server address that the client socket is going to connect
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET; 
	server_address.sin_addr.s_addr = inet_addr(address);
	server_address.sin_port = htons(port);

	while(1) {
		if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(struct sockaddr_in)) == 0) {
			break;
		}
				
		close(consocket);
		usleep(1000);
	}
}

void NetIO::Send_Data_Internal(const void* data, int LEN) {
	size_t SENTED_LEN = 0;
	while(SENTED_LEN < LEN) {
		size_t REST_LEN = fwrite(SENTED_LEN + (char*)data, 1, LEN - SENTED_LEN, stream);
		if (REST_LEN >= 0){
			SENTED_LEN += REST_LEN;
		}
		else{
			fprintf(stderr,"error: net_send_data %d\n", REST_LEN);
		}
		has_sent = true;
	}
}

void NetIO::Receive_Data_Internal(void* data, int LEN) {
	if(HAS_SENT) fflush(stream);
	HAS_SENT = false;
	size_t SENTED_LEN = 0;
	while(SENTED_LEN < LEN) {
		size_t REST_LEN = fread(SENTED_LEN + (char*)data, 1, LEN - SENTED_LEN, stream);
		if (REST_LEN >= 0){
			SENTED_LEN += REST_LEN;
		}
		else{ 
			fprintf(stderr,"error: net_send_data %d\n", REST_LEN);
		}
	}
}

void NetIO::Sync() {
	int tmp = 0;
	if(is_server) {
		send_data_internal(&tmp, 1);
		recv_data_internal(&tmp, 1);
	} 
	else {
		recv_data_internal(&tmp, 1);
		send_data_internal(&tmp, 1);
		flush();
	}
}

#endif  //NETWORK_IO_CHANNEL