# sniffer

Учебная утилита на Python для захвата сетевого трафика в Linux: пишет классический **pcap**, показывает пакеты в терминале в реальном времени, разбирает Ethernet / IPv4 / IPv6 / TCP / UDP и умеет простой фильтр.

Только **Linux**. Захват — через raw-сокет `AF_PACKET` (нужны права root или `CAP_NET_RAW`). Сторонние библиотеки для захвата/разбора **не** используются.

## Требования

- Python **3.10+**
- Linux с поддержкой `AF_PACKET`
- Для разработки тестов: `pip install pytest ruff`
- Для проверки pcap: `tcpdump` (и опционально `tshark`)

## Установка и запуск

Из корня репозитория (отдельный install не нужен — пакет лежит в `sniffer/`):

```bash
python3 -m sniffer -h
sudo python3 -m sniffer -i eth0 -c 20
```

Без root сокет не откроется; утилита выведет подсказку вида:

```text
sniffer: permission denied opening AF_PACKET socket.
Hint: run with root privileges, e.g. `sudo python3 -m sniffer ...`
```

## Флаги

```text
python3 -m sniffer [-i IFACE] [-w FILE.pcap] [-c COUNT] [-s SNAPLEN] [-p] [-x] [-q] [-f FILTER]
```

| Флаг | Смысл |
|---|---|
| `-i, --interface` | интерфейс; по умолчанию все (сокет не биндится) |
| `-w, --write` | писать пакеты в pcap-файл |
| `-c, --count` | остановиться после N пакетов, прошедших фильтр |
| `-s, --snaplen` | макс. длина сохраняемого пакета (по умолчанию 65535, диапазон 1..262144) |
| `-p, --promisc` | включить promiscuous mode (нужен `-i`) |
| `-x, --hex` | hex/ASCII-дамп каждого пакета (как `tcpdump -X`) |
| `-q, --quiet` | не печатать пакеты (только файл и итоговая статистика) |
| `-f, --filter` | простой фильтр (см. ниже) |
| `-h, --help` | справка |

## Фильтр

Условия соединяются через `and` (без `or` / `not` / скобок):

- протоколы: `tcp`, `udp`, `ip4`, `ip6`
- адрес: `host ADDR`, `src host ADDR`, `dst host ADDR` (IPv4 и IPv6)
- порт: `port N`, `src port N`, `dst port N`

Пример:

```bash
sudo python3 -m sniffer -i eth0 -f "tcp and port 443 and host 10.0.0.1"
```

Ошибка синтаксиса → сообщение с проблемным токеном и код выхода **2**.

## Примеры

Захват 50 пакетов с `eth0` в файл:

```bash
sudo python3 -m sniffer -i eth0 -w out.pcap -c 50 -q
tcpdump -nr out.pcap | wc -l   # ожидается 50
```

Только UDP на loopback, с дампом:

```bash
sudo python3 -m sniffer -i lo -f "udp and port 9999" -x -c 10
```

На `Ctrl+C` (SIGINT) / SIGTERM файл закрывается корректно, в stderr печатается статистика:

```text
sniffer: captured=... passed=... written=... skipped=...
```

`skipped` — кадры с не-Ethernet `hatype` (не пишутся в pcap). На `lo` дубликаты `PACKET_OUTGOING` отбрасываются.

## Формат строки

```text
12:34:56.789012 eth0 IPv4 TCP 192.168.1.5:51234 -> 93.184.216.34:443 [SYN,ACK] len=74
```

## Тесты

```bash
python3 -m pytest
python3 -m ruff check .
```

Интеграционные тесты (`tests/test_integration.py`) помечены `@pytest.mark.root` и **пропускаются** без root / вне Linux. Под root:

```bash
sudo python3 -m pytest -m root
```

## Ограничения

- Только Linux (`AF_PACKET`).
- Фильтр — только `and`, без BPF.
- Один VLAN-тег 802.1Q; IPv6 extension headers: Hop-by-Hop, Routing, Fragment, Destination Options.
- Обрезанные/битые пакеты не роняют процесс: помечаются `truncated` / `malformed` и при необходимости всё равно пишутся в pcap.
