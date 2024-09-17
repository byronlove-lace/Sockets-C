#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>

//TODO: Make this into a prog that can take an addr and return html

#define BUFF_SIZE 4096

char* smart_cat(char* dest, const char* src) {
	size_t dest_len = strlen(dest);
	size_t src_len = strlen(src);
	size_t new_len = dest_len + src_len + 1;

	char* new_string = (char*)malloc(new_len * sizeof(char));

	if (new_string == NULL) {
		return NULL;
	}

	memset(new_string, 0, new_len * sizeof(char));

	strcat(new_string, dest);
	strcat(new_string, src);

	return new_string;
}

int status, socketfd, connection;
struct addrinfo hints, *res;
char* domain_name = "libgen.rs";

int main(void) {
	// SET UP ADDRINFO STRUCTS
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	// NOTE: Do dynamic port checking with URL parsing here
	status = getaddrinfo(domain_name, "443", &hints, &res);
	if (status != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		freeaddrinfo(res);
		return 1;
	}

	// CREATE SOCKET
	socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (socketfd == -1) {
		perror("Failed to create socket: ");
		freeaddrinfo(res);
		return 1;
	}

	// CONNECT
	connection = connect(socketfd, res->ai_addr, res->ai_addrlen);
	if (connection == -1) {
		perror("Failed to connect: ");
		freeaddrinfo(res);
		return 1;
	}

	// creates a local context that helps track handshake parameters and state of SSL connection
	SSL_CTX* ctx = SSL_CTX_new(TLS_method());
	// creates ssl endpoint
	SSL* ssl = SSL_new(ctx);
	// attach SSL stack to socket
	SSL_set_fd(ssl, socketfd);
	// Initiate handshake
	int ssl_connection  = SSL_connect(ssl);
	if (ssl_connection != 1) {
		fprintf(stderr, "Error connecting to SSL: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	// BUG: Getting 400 on the request: actually due to my not understanding HTTPS
	char* request = NULL;
	char* requestline = NULL;
	char* headers = NULL; 
	char* method = "GET";
	char* version = "HTTP/1.1";
	char* host_header = smart_cat("Host: ", domain_name);
	host_header = smart_cat(host_header, "\r\n");
	char* user_agent_header = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0\r\n";
	char* accept_header = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n";
	char* accept_language_header = "Accept-Language: en-GB,en;q=0.5\r\n";
	char *accept_encoding_header = "Accept-Encoding: gzip, deflate, br\r\n";
	char* connection_header = "Connection: keep-alive\r\n";
	char *dnt_header = "DNT: 1\r\n";
	char *upgrade_insecure_header = "Upgrade-Insecure-Requests: 1\r\n";
	
	requestline = smart_cat(method, " / ");
	requestline = smart_cat(requestline, version);
	requestline = smart_cat(requestline, "\r\n");

	headers = smart_cat(host_header, user_agent_header);
	headers = smart_cat(headers, accept_header);
	headers = smart_cat(headers, accept_language_header);
	headers = smart_cat(headers, accept_encoding_header);
	headers = smart_cat(headers, dnt_header);
	headers = smart_cat(headers, connection_header);
	headers = smart_cat(headers, upgrade_insecure_header);

	request = smart_cat(requestline, headers);
	request = smart_cat(request, "\r\n");
	printf("%s", request);

	// SEND REQUEST
	int request_len, bytes_sent, bytes_left;
	int bytes_sent_total = 0;
	request_len = strlen(request);
	bytes_left = request_len;

	// BUG: TEST THIS
	int ret_code = SSL_write(ssl, request, request_len);
	if (ret_code <= 0) {
		int ssl_error = SSL_get_error(ssl, ret_code);
		fprintf(stderr, "Error writing SSL: %s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	/*
	while (bytes_left > 0) {
		bytes_sent = send(socketfd, request + bytes_sent_total, bytes_left, 0);
		if (bytes_sent == -1) {
			perror("Failed to send request");
			return 1;
		}
		bytes_left -= bytes_sent;
		bytes_sent_total += bytes_sent;
	}
	*/

	// CLEAN UP
	free(host_header);
	free(headers);
	free(requestline);
	free(request);

	// RECIEVE RESPONSE
	char response_buff[BUFF_SIZE] = {0};
	int read_success = SSL_read(ssl, response_buff, BUFF_SIZE-1);
	if (read_success <= 0) {
		fprintf(stderr, "Failed to read response: %s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	printf("%s\n", response_buff);

	// DECOMPRESS THE RESPONSE (FUN!)
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = read_success;
	strm.next_in = (Bytef*)response_buff;

	if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
		fprintf(stderr, "Failed to initialize gzip decompression\n");
		return 1;
	}

	char decompressed_buff[BUFF_SIZE] = {0};
	strm.avail_out = BUFF_SIZE - 1;
	strm.next_out = (Bytef*)decompressed_buff;

	int ret = inflate(&strm, Z_FINISH);
	if (ret != Z_STREAM_END) {
		fprintf(stderr, "Failed to decompress response: %d\n", ret);
		inflateEnd(&strm);
		return 1;
	}

	inflateEnd(&strm);

	printf("%s\n", decompressed_buff);
	/*
	int bytes_recieved, total_bytes_recieved = 0;

	while (1) {
		bytes_recieved = recv(socketfd, response_buff + total_bytes_recieved, BUFF_SIZE - total_bytes_recieved, 0);
		printf("Bytes Recieved: %d", bytes_recieved);
		if (bytes_recieved == -1) {
			perror("Error recieving response from server. ");
			return 1;
		} else if (bytes_recieved == 0) {
			// Connection close by server
			break;
		}
		total_bytes_recieved += bytes_recieved;

		if (total_bytes_recieved == BUFF_SIZE) {
			perror("Response buffer is full. Unable to recieve more data. ");
			return 1;
		}
	}

	response_buff[total_bytes_recieved] = '\0';

	printf("Response:\n%s\n", response_buff);
	*/

	// CLEAN UP
	close(socketfd);
	freeaddrinfo(res);
}

