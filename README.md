### **1. 패킷(PACKET)과 캡슐화(Encapsulation)**

네트워크에서 데이터는 계층을 거치며 여러 정보를 덧붙여 전송

이 과정을 캡슐화라고 하며 각 계층은 자신의 역할에 따라 헤더를 붙인다.

예를 들어 Discord 같은 애플리케이션을 사용할 때

- 애플리케이션에서 생성된 메시지는
- 전송 계층으로 전달되어 TCP/UDP 헤더가 붙고 세그먼트가 된다.
- 그 다음 네트워크 계층에서 IP 헤더가 붙어 패킷이 된다.
- 최종적으로 데이터 링크 계층에서 MAC 주소와 함께 프레임이 만들어져 실제 전송

---

### **2. 네트워크 계층 구조 요약**

- 4계층 (전송계층, Transport Layer): 애플리케이션 간 데이터 전송을 담당. TCP, UDP 등 사용
- 3계층 (네트워크 계층, Network Layer): 목적지까지의 최적 경로 결정 (라우팅)
- 2계층 (데이터 링크 계층, Data Link Layer): 물리적인 주소(MAC)를 기반으로 네트워크 내 전송 처리

---

### **3. 패킷 스니핑(Packet Sniffing)**

네트워크를 통해 흐르는 데이터를 가로채어 분석하는 기술

- 보안 관리자는 이를 통해 트래픽 분석, 문제 해결, 이상 탐지에 사용
- 공격자는 이 기술을 활용해 민감한 정보(계정, 인증 토큰 등)를 탈취

---

### **4. PCAP API**

PCAP(Packet Capture) API는 운영체제에서 패킷 캡처 기능에 접근할 수 있도록 도와주는 표준 인터페이스

- 다양한 필터링 기능을 제공하며, 플랫폼 간 일관성을 보장
- 내부적으로는 OS에 따라 다르게 구현되어 있지만 개발자는 동일한 방식으로 사용할 수 있음
- 설치 예시: `sudo apt install libpcap-dev`

---

### **5. UDP 기반 공격 예시 – Fraggle Attack**

- Fraggle 공격은 UDP의 Echo 프로토콜(포트 7)을 악용
- 브로드캐스트 주소를 대상으로 요청을 보내, 네트워크 내 다수의 호스트가 응답을 하도록 유도
- 이 응답들이 모두 공격 대상에게 몰리며 트래픽 폭주 유발
- 공격자는 출발지 주소를 피해자의 IP로 위조하여 공격을 실행

---

### **6. TCP SYN Flooding Attack (SYN 플러딩 공격)**

- TCP의 3-Way Handshake 과정을 악용한 서비스 거부(DoS) 공격
1. 공격자는 SYN 패킷을 대량 전송
2. 서버는 SYN+ACK으로 응답하고 연결 대기 큐(SYN Queue)에 저장
3. 하지만 마지막 ACK를 받지 않으면 연결이 완성되지 않음
4. 이 상태가 쌓이면 큐가 가득 차고 정상적인 연결이 불가능해짐
- 주로 위조된 IP 주소를 사용해 탐지를 어렵게 하며
- 방화벽이나 SYN 쿠키 같은 기법으로 방어 가능

---

### **7. TCP 연결 종료 공격 - TCP RST Injection**

- TCP 세션을 RST(Reset) ****패킷 하나로 종료 가능
- 공격자가 통신 중인 A와 B 사이에 위조된 TCP RST 패킷을 보내면 연결은 즉시 끊김
- 이 기법은 민감한 서비스나 세션을 끊는 데 악용될 수 있음

---

### **8. Reverse Shell (역방향 셸)**

- 시스템의 취약점을 이용해 원격에서 명령어를 실행할 수 있도록 하는 해킹 기술
- 피해자 시스템이 공격자에게 먼저 연결을 시도하는 구조
- 공격자는 이 연결을 통해 시스템 내부를 탐색하거나 명령어를 실행할 수 있음

---

### **9. PCAP Programming 실습**

---

### A. libpcap 설치한다.

![image.png](attachment:1e195ec7-ac03-43a0-a38d-2b163f0eeed4:image.png)

### B. 코드를 작성한다.

![image.png](attachment:67f7bc19-5e4a-4c16-af37-1f8c3d676f90:image.png)

```jsx
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

#define ETHERNET_HEADER_LEN 14

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);
    int ip_header_len = ip_header->ip_hl * 4;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;

    const u_char *payload = packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;
    int payload_len = header->len - (ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len);

    printf("\n=== PACKET ===\n");

    // Ethernet
    printf("Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    // IP
    printf("IP Src: %s\n", inet_ntoa(ip_header->ip_src));
    printf("IP Dst: %s\n", inet_ntoa(ip_header->ip_dst));

    // TCP
    printf("TCP Src Port: %d\n", ntohs(tcp_header->th_sport));
    printf("TCP Dst Port: %d\n", ntohs(tcp_header->th_dport));

    // Payload
    if (payload_len > 0) {
        printf("Payload (%d bytes): ", payload_len);
        for (int i = 0; i < payload_len && i < 32; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("Payload (0 bytes)\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf); // 인터페이스 이름 확인 필요
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

```

### C. 컴파일 한다.

![image.png](attachment:3c2e8ab1-ed44-43f5-b0e7-dbecb5e6ff60:image.png)

### D. 관리자 권한으로 실행한다.

![image.png](attachment:5ff92f97-a587-4372-b2af-9213017bcf49:image.png)

![image.png](attachment:e197808c-5288-4164-8cf9-d27a383ed4ed:image.png)

![image.png](attachment:f1c12153-20a8-4c9b-b9ad-d25a71b45545:image.png)

![image.png](attachment:9c516048-3152-4446-a2f0-74a8d38af09c:image.png)

![image.png](attachment:ba792cb8-ced4-400a-83bd-e9f9a3d8cabd:image.png)

### 10. 구현 기능

### 10.1 패킷 캡처 및 필터링

- TCP 프로토콜만 대상으로 패킷 캡처 수행
- 패킷 캡처 시 UDP 패킷은 제외하고 TCP 패킷만 처리

### 10.2 패킷 헤더 정보 출력

- **Ethernet 헤더**: 출발지(Source) MAC 주소, 목적지(Destination) MAC 주소
- **IP 헤더**: 출발지 IP 주소, 목적지 IP 주소, IP 헤더 길이 활용
- **TCP 헤더**: 출발지 포트, 목적지 포트

### 10.3 패킷 데이터 분석

- 패킷 페이로드(데이터) 크기 표시
- 페이로드 내용 일부 출력 (가독성을 위해 적절히 표현)
- 각 패킷을 === PACKET === 구분자로 명확히 구분

### 11. 구현 결과 분석

### 11.1 패킷 통신 흐름 분석

구현 결과에서 관찰된 주요 패킷 통신 패턴은

1. **웹 통신(HTTP) 패턴**:
    - TCP 목적지 포트 80번을 사용하는 패킷 확인
    - 클라이언트(192.168.190.131)에서 서버(185.125.190.49)로의 요청과 응답 확인
    - HTTP 통신으로 보이는 패턴 식별
2. **로컬 네트워크 통신**:
    - 192.168.190.x 대역 IP 주소 간 통신 확인
    - 다양한 TCP 포트 번호 사용 관찰
3. **패킷 크기 분석**:
    - 다양한 크기의 페이로드 확인 (0바이트부터 93바이트까지)
    - TCP 연결 수립 및 종료 시 페이로드가 없는(0바이트) 패킷 확인

### 11.2 MAC 주소 분석

반복적으로 등장하는 MAC 주소 패턴:

- 00:0c:29:1a:61:37
- 00:50:56:ea:00:93
- VMware 가상 환경에서 사용되는 MAC 주소로 VMware 네트워크 어댑터의 특성 확인 가능
