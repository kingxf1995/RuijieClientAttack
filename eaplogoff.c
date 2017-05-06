#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

bool parse_mac(const char* str, uint8_t mac[6])
{
    int values[6];
    int i;

    if( 6 == sscanf( str, "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5] ) )
    {
        /* convert to uint8_t */
        for( i = 0; i < 6; ++i )
            mac[i] = (uint8_t) values[i];
        return true;
    }

    else
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    uint8_t buffer[128];
    if (argc != 3)
    {
        printf("Usage: %s ifname macaddr\n", argv[0]);
        exit(0);
    }

    char *ifname = argv[1];
    char *macstr = argv[2];

    pcap_t *iface = pcap_open_live(ifname, 2048, true, 1000, (char*)buffer);
    if (!iface)
    {
        printf("error: %s\n", (char*)buffer);
        return 1;
    }

    static uint8_t template[] = {
        0x00, 0x1A, 0xA9, 0x17, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x01, 0x02
    };

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, template, sizeof(template));
    if (!parse_mac(argv[2], buffer+6))
    {
        printf("mac address format error\n");
        return 1;
    }

    pcap_sendpacket(iface, buffer, sizeof(buffer));
    pcap_close(iface);
    return 0;
}
