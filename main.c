
#include "shared.h"
#include "starv.h"
#include "rogue.h"

int main()
{
    int sock;
    sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sock == -1)
    {
        fprintf(stderr,"Socket Failed");
    }

    int starv_res = server_starvation(&sock);
    if(starv_res == -1)
    {
        return -1;
    }

    if(starv_res == STARV_SUCCESS)
    {
        int check_return = rogue_server(&sock);
        if(check_return == ROGUE_SUCCESS)
        {
            return 0;
        }
    }
    
    return 0;
}