#include "../bpf/packet.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
static int quiet(enum libbpf_print_level,const char*,va_list){return 0;}
static void need(bool value){if(!value)throw std::runtime_error("packet verification failed");}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    try{
        libbpf_set_print(quiet);auto *raw=bpf_object__open_file(argv[1],nullptr);need(raw&&!libbpf_get_error(raw));
        std::unique_ptr<bpf_object,decltype(&bpf_object__close)> owner(raw,bpf_object__close);need(!bpf_object__load(raw));
        auto *program=bpf_object__find_program_by_name(raw,"count_packets");need(program);
        int ports=bpf_object__find_map_fd_by_name(raw,"ports"),packets=bpf_object__find_map_fd_by_name(raw,"packets");
        uint16_t port=443;uint8_t enabled=1;need(!bpf_map_update_elem(ports,&port,&enabled,BPF_ANY));
        auto packet=[](unsigned flags,bool udp=false,bool ipv6=false){
            std::vector<uint8_t> data(14+(ipv6?40:20)+(udp?8:20),0);
            data[12]=ipv6?0x86:8;data[13]=ipv6?0xdd:0;size_t ip=14,transport=ip+(ipv6?40:20);
            data[ip]=ipv6?0x60:0x45;if(ipv6){data[ip+6]=udp?17:6;data[ip+5]=udp?8:20;}
            else {data[ip+9]=udp?17:6;data[ip+2]=0;data[ip+3]=data.size()-14;}
            data[transport+2]=1;data[transport+3]=0xbb;
            if(!udp){data[transport+12]=0x50;data[transport+13]=flags;}return data;
        };
        auto run=[&](const std::vector<uint8_t>&data){bpf_test_run_opts options{};options.sz=sizeof(options);
            options.data_in=data.data();options.data_size_in=data.size();options.repeat=1;
            need(!bpf_prog_test_run_opts(bpf_program__fd(program),&options));need(options.retval==0);};
        run(packet(2));run(packet(16));run(packet(18));run(packet(5));run(packet(0,true));run(packet(16,false,true));
        auto vlan=packet(2);vlan.insert(vlan.begin()+14,4,0);vlan[12]=0x81;vlan[13]=0;vlan[16]=8;vlan[17]=0;run(vlan);
        auto unrelated=packet(2);unrelated[36]=0;unrelated[37]=80;run(unrelated);
        auto truncated=packet(2);truncated.resize(64);truncated[14]=0x4f;run(truncated);
        auto fragment=packet(2);fragment[20]=0;fragment[21]=1;run(fragment);
        uint32_t key=0;int cpus=libbpf_num_possible_cpus();need(cpus>0);std::vector<scdn_packet_counts> rows(cpus);
        need(!bpf_map_lookup_elem(packets,&key,rows.data()));std::array<uint64_t,10> total{};
        for(auto &row:rows){std::array<uint64_t,10> data{};memcpy(data.data(),&row,sizeof(row));for(unsigned i=0;i<10;i++)total[i]+=data[i];}
        need(total[0]==6&&total[2]==3&&total[3]==3&&total[4]==1&&total[5]==2&&total[6]==1&&total[7]==1&&total[8]==1);
        std::cout<<"{\"passed\":true,\"check_count\":11,\"scope\":\"real_kernel_bpf_program_test_run\"}\n";return 0;
    }catch(...){std::cerr<<"BPF packet verification failed\n";return 1;}
}
