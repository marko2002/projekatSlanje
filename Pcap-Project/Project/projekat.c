// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba6.c
// ================================================================

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define HAVE_STRUCT_TIMESPEC
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#include "pthread.h"
#include "semaphore.h"

#define DATA_SIZE_IN_PACKET 494

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);

void packet_handler_eth(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void packet_handler_wifi(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void packet_handler2(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void* listenOverWiFi();



FILE* fp;
int i = 0;
int j = 0;
int k = 0;
unsigned char* fileName = "";
unsigned char* nmbrOfPackets = "";
int NMBR_OF_PACKETS = 0;
pcap_t* device_handle;
pcap_t* device_handle_wifi;
unsigned long startTime_;
static sem_t semaphore;



int main()
{
	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_if_t* device_wifi;

	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	char filter_exp[] = "udp and ip";
	char filter_exp_wifi[] = "udp and ip";
	struct bpf_program fcode;


	int result;							// result of pcap_next_ex function
	struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
	const unsigned char* packet_data;	// packet content

	pthread_t wifi_thread;


	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// Chose one device from the list
	device = select_device(devices);

	// Check if device is valid
	if (device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	// Chose one device from the list
	device_wifi = select_device(devices);

	// Check if device is valid
	if (device_wifi == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}



	// Open the capture device
	if ((device_handle = pcap_open_live(device->name,		// name of the device
		65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
		0,							// Nenulta vrednost oznacava slobodan (eng. Promiscous) rezim adaptera
		10,							// read timeout
		error_buffer				// buffer where error message is stored
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
		pcap_freealldevs(devices);
		return -1;
	}


#ifdef _WIN32
	if (device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;
#else
	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
#endif

	/************************************************************************************************************************************/


	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}


	/******************************************************************************************************************************************/

	/************************************************************************************************************************************/
	// Open the capture device  ****** W I F I ********

	if ((device_handle_wifi = pcap_open_live(device_wifi->name,		// name of the device
		65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
		0,							// Nenulta vrednost oznacava slobodan (eng. Promiscous) rezim adaptera
		10,							// read timeout
		error_buffer				// buffer where error message is stored
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device_wifi->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Compile the filter
	if (pcap_compile(device_handle_wifi, &fcode, filter_exp, 1, 0xffffff) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle_wifi, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
	printf("\nListening on %s...\n", device->description);
	printf("\nListening on %s...\n", device_wifi->description);
	/******************************************************************************************************************************************/
	// At this point, we don't need any more the device list. Free it
	pcap_freealldevs(devices);


	// Retrieve the packets
	pcap_loop(device_handle, 0, packet_handler2, NULL);


	fp = fopen(fileName, "wb");

	if (strlen(nmbrOfPackets) == 5)
	{
		NMBR_OF_PACKETS = (nmbrOfPackets[0] - '0') * 10000 + (nmbrOfPackets[1] - '0') * 1000 + (nmbrOfPackets[2] - '0') * 100 + (nmbrOfPackets[3] - '0') * 10 + (nmbrOfPackets[4] - '0');
	}
	else if (strlen(nmbrOfPackets) == 4)
	{
		NMBR_OF_PACKETS = (nmbrOfPackets[0] - '0') * 1000 + (nmbrOfPackets[1] - '0') * 100 + (nmbrOfPackets[2] - '0') * 10 + (nmbrOfPackets[3] - '0');
	}
	else if (strlen(nmbrOfPackets) == 3)
	{
		NMBR_OF_PACKETS = (nmbrOfPackets[0] - '0') * 100 + (nmbrOfPackets[1] - '0') * 10 + (nmbrOfPackets[2] - '0');
	}
	else if (strlen(nmbrOfPackets) == 2)
	{
		NMBR_OF_PACKETS = (nmbrOfPackets[0] - '0') * 10 + (nmbrOfPackets[1] - '0');
	}
	else
		NMBR_OF_PACKETS = (nmbrOfPackets[0] - '0');


	//**************************************************************************************************************************************

	unsigned int len = 0;
	unsigned char* ACK = NULL;

	ACK = setup_custom_header(&len, ACK, NMBR_OF_PACKETS);
	ACK = setup_udp_header(&len, ACK);
	ACK = setup_ipv4_header(&len, ACK, 0);
	ACK = setup_ethernet_header(&len, ACK, 0);
	if (pcap_sendpacket(device_handle, ACK, len) == -1)
	{
		printf("Packet %d not sent!\n", i);
		return -1;
	}

	free(ACK);

	printf("\nReceiving file: %s\nTotal number of sent packages: %d\n\n", fileName, NMBR_OF_PACKETS);

	/*######################################*/
	/*time_t timestamp;	   // Raw time (bits) when packet is received
	struct tm* local_time; // Local time when packet is received
	char time_string[16];  // Local time converted to string
	char start_time[16];
	char end_time[16];

	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);// Convert the timestamp to readable format


	startTime_ = timeGetTime();
	memcpy(start_time, time_string, sizeof(time_string));
	printf("Start time: %s\n\n", start_time);*/

	/*######################################*/
	startTime_ = timeGetTime();

	pthread_create(&wifi_thread, NULL, listenOverWiFi, NULL);
	sem_init(&semaphore, 0, 1); //If the pshared argument has a non - zero value, then the semaphore is shared between processes;


	pcap_loop(device_handle, 0, packet_handler_eth, NULL);
	//pcap_loop(device_handle_wifi, 0, packet_handler_wifi, NULL);

	listenOverWiFi();



	//memcpy(end_time, time_string, sizeof(time_string));
	//printf("\nEnd time:\t%s\n", end_time);
	double diffInMilliSeconds = timeGetTime() - startTime_;
	printf("Elapsed time: %f seconds\n", diffInMilliSeconds/1000);

	printf("\nFile has been received!\n\n");

	pcap_close(device_handle);
	pcap_close(device_handle_wifi);

	pthread_join(wifi_thread, NULL);
	sem_destroy(&semaphore);
	fclose(fp);


	return 0;
}

// This function provide possibility to choose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices)
{
	int device_number;
	int ii = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;	// Iterator for device list

						// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++ii, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (ii == 0)
	{
		printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	printf("Enter the interface number (1-%d):", ii);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > ii)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, ii = 0; ii< device_number - 1; device = device->next, ii++);

	return device;
}


void packet_handler_eth(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{

	unsigned short src_port;

	// Retrive the position of the ethernet header
	ethernet_header* eh = (ethernet_header*)packet_data;

	// Check the type of ethernet data
	if (ntohs(eh->type) != 0x0800) // Ipv4 = 0x0800
		return;

	// Retrieve the position of the IP header
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	// Check the type of ip data
	if (ih->next_protocol != 0x11) // UDP = 0x11
		return;

	// Retrieve the position of the UDP header
	int length_bytes = ih->header_length * 4; // header length is calculated
											  // using words (1 word = 4 bytes)

	udp_header* uh = (udp_header*)((unsigned char*)ih + length_bytes);

	src_port = ntohs(uh->src_port);

	unsigned char * custom_header = packet_data + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) - 4;

	if (ih->src_addr[0] == 10 && ih->src_addr[1] == 81 && ih->src_addr[2] == 31 && ih->src_addr[3] == 59 && src_port == 8080 && strcmp(custom_header, "BokaMare") == 0)
	{
		long id = ((*(packet_data + 51)) << 32) + ((*(packet_data + 52)) << 24) + ((*(packet_data + 53)) << 16) + ((*(packet_data + 54)) << 8) + *(packet_data + 55);
		sem_wait(&semaphore);
			fseek(fp, (id - 3)*DATA_SIZE_IN_PACKET, SEEK_SET);
			fwrite(packet_data + 56, 1, (ntohs(uh->datagram_length) - 22), fp);
		sem_post(&semaphore);

		i++;

				unsigned int len = 0;
				unsigned char* ACK = NULL;

				ACK = setup_custom_header(&len, ACK, id);
				ACK = setup_udp_header(&len, ACK);
				ACK = setup_ipv4_header(&len, ACK, 0);
				ACK = setup_ethernet_header(&len, ACK, 0);

				if (pcap_sendpacket(device_handle, ACK, len) == -1)
				{
					printf("Packet %d not sent!\n", i);
					return -1;
				}

		free(ACK);

		printf("<<ETH>> adresa posiljaoca: %u.%u.%u.%u, id paketa->%u , velicina paketa[%d]: %d byte\n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3], id, i, packet_header->len);

	}

	if (i == (NMBR_OF_PACKETS/2)) { // -----> kada saljemo samo preko eth (i == (NMBR_OF_PACKETS))
		pcap_breakloop(device_handle);
	}
	return;
}


void packet_handler_wifi(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{

	unsigned short src_port;

	// Retrive the position of the ethernet header
	ethernet_header* eh = (ethernet_header*)packet_data;

	// Check the type of ethernet data
	if (ntohs(eh->type) != 0x0800) // Ipv4 = 0x0800
		return;

	// Retrieve the position of the IP header
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	// Check the type of ip data
	if (ih->next_protocol != 0x11) // UDP = 0x11
		return;

	// Retrieve the position of the UDP header
	int length_bytes = ih->header_length * 4; // header length is calculated
											  // using words (1 word = 4 bytes)

	udp_header* uh = (udp_header*)((unsigned char*)ih + length_bytes);

	src_port = ntohs(uh->src_port);

	unsigned char * custom_header = packet_data + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) - 4;

	if (ih->src_addr[0] == 192 && ih->src_addr[1] == 168 && ih->src_addr[2] == 123 && ih->src_addr[3] == 16 && src_port == 8080 && strcmp(custom_header, "BokaMare") == 0)
	{

		long id = ((*(packet_data + 51)) << 32) + ((*(packet_data + 52)) << 24) + ((*(packet_data + 53)) << 16) + ((*(packet_data + 54)) << 8) + *(packet_data + 55);
		sem_wait(&semaphore);
			fseek(fp, (id - 3)*DATA_SIZE_IN_PACKET, SEEK_SET);
			fwrite(packet_data + 56, 1, (ntohs(uh->datagram_length) - 22), fp);
		sem_post(&semaphore);

		k++;

		unsigned int len = 0;
		unsigned char* ACK = NULL;

		ACK = setup_custom_header(&len, ACK, id);
		ACK = setup_udp_header(&len, ACK);
		ACK = setup_ipv4_header(&len, ACK, 1);
		ACK = setup_ethernet_header(&len, ACK, 1);
		if (pcap_sendpacket(device_handle_wifi, ACK, len) == -1)
		{
			printf("Packet %d not sent!\n", k);
			return -1;
		}

		free(ACK);

		printf("<<WIFI>> adresa posiljaoca: %u.%u.%u.%u, id paketa->%u , velicina paketa[%d]: %d byte\n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3], id, k, packet_header->len);

	}
	if (NMBR_OF_PACKETS % 2 == 0)	
	{
		

		if (k == NMBR_OF_PACKETS/2 ) // kada samo preko wi fi (k == NMBR_OF_PACKETS  )
		{
			
			pcap_breakloop(device_handle_wifi);
		}
	}
	else
	{

		if (k == NMBR_OF_PACKETS/2 + 1 )//kada samo preko wi fi (k == NMBR_OF_PACKETS  )
		{
			
			pcap_breakloop(device_handle_wifi);
		}
	}

	return;
}


void packet_handler2(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{


	ethernet_header* eh = (ethernet_header*)packet_data;

	if (ntohs(eh->type) != 0x0800) // Ipv4 = 0x0800
		return;

	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	if (ih->next_protocol != 0x11) // UDP = 0x11
		return;

	int length_bytes = ih->header_length * 4; // header length is calculated
											  // using words (1 word = 4 bytes)
	udp_header* uh = (udp_header*)((unsigned char*)ih + length_bytes);


	unsigned char * custom_header = packet_data + 42;



	if (j == 0 && strcmp(custom_header, "BokaMare") == 0)
	{
		fileName = (packet_data + 56);
		j++;
	}
	else if (j == 1 && strcmp(custom_header, "BokaMare") == 0)
	{
		nmbrOfPackets = (packet_data + 56);
		pcap_breakloop(device_handle);
	}
	else
	{
		printf("WRONG PACKET!!\n");
	}

}

void* listenOverWiFi()
{
	pcap_loop(device_handle_wifi, 0, packet_handler_wifi, NULL);
}







