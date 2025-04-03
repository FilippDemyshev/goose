import time
from datetime import datetime, timezone
from pprint import pprint
from scapy.all import sniff


class GooseParser:
    def __init__(self, frame_data):
        self.raw_data = frame_data
        self.frame = None
        self.pdu = None
        self.all_data = None

    def parse_goose_frame(self):
        """Parse Ethernet frame containing GOOSE message."""
        try:
            if not self.raw_data:
                raise ValueError("Empty input string")

            cadr = self.raw_data.split()

            if len(cadr) < 14:
                raise ValueError(f"Frame too short. Expected min 14 bytes, got {len(cadr)}")

            ethernet_header = cadr[0:14]

            for byte in ethernet_header:
                if not all(c in '0123456789abcdefABCDEF' for c in byte) or len(byte) != 2:
                    raise ValueError(f"Invalid byte: {byte}")

            ethertype = cadr[12] + cadr[13]
            if ethertype.lower() != '88b8':
                return None, "Not a GOOSE frame"

            dst_mac = ':'.join(ethernet_header[0:6]).upper()
            src_mac = ':'.join(ethernet_header[6:12]).upper()

            if len(cadr) < 18:
                raise ValueError("Frame too short for APPID analysis")

            appid = cadr[14] + cadr[15]

            try:
                length = int(cadr[16] + cadr[17], 16)
            except ValueError:
                raise ValueError(f"Invalid length value: {cadr[16] + cadr[17]}")

            if len(cadr) < 22:
                reserved_1 = reserved_2 = None
            else:
                reserved_1 = cadr[18] + cadr[19]
                reserved_2 = cadr[20] + cadr[21]

            if len(cadr) < 14 + length:
                raise ValueError(f"Declared length ({length} bytes) > actual ({len(cadr) - 14} bytes)")

            goose_pdu = cadr[22:]
            if not goose_pdu:
                raise ValueError("Missing GOOSE PDU")

            self.frame = {
                'dst_mac': dst_mac,
                'src_mac': src_mac,
                'ethertype': ethertype,
                'appid': appid,
                'length': length,
                'reserved_1': reserved_1,
                'reserved_2': reserved_2,
                'pdu': goose_pdu
            }
            if self.frame['pdu'][1] == '82' and len(self.frame['pdu']) >= 4:
                self.pdu = self.frame['pdu'][4:]  # Пропускаем 4 байта (тег + длина)
            else:
                self.pdu = self.frame['pdu'][3:]  # Пропускаем 3 байта (тег + длина)
            return self.frame

        except Exception as e:
            return None, str(e)


    @staticmethod
    def parse_goose_time(hex_parts):
        """Парсинг временной метки GOOSE из hex-данных с учётом временной зоны"""
        try:
            # Преобразуем hex в байты
            bytes_data = bytes.fromhex(''.join(hex_parts))

            # Проверяем длину данных
            if len(bytes_data) != 8:
                return f"Неверная длина временной метки: ожидается 8 байт, получено {len(bytes_data)}"

            # Распаковываем секунды и наносекунды (big-endian)
            seconds = int.from_bytes(bytes_data[:4], byteorder='big')
            nanoseconds = int.from_bytes(bytes_data[4:], byteorder='big')

            # Преобразуем в datetime с явным указанием UTC
            timestamp = seconds + nanoseconds / 1e9
            utc_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)

            # Форматируем вывод
            return utc_time.strftime('%b %d, %Y %H:%M:%S.%f')[:-3] + ' UTC'

        except Exception as e:
            return f"Ошибка парсинга времени: {str(e)}"


    def parse_goose_pdu(self):
        """Парсинг GOOSE PDU из hex-строки"""
        pdu = self.pdu.split() if isinstance(self.pdu, str) else self.pdu
        i = 0
        result = {
            'gocbRef': None,
            'timeAllowedToLive': None,
            'datSet': None,
            'goID': None,
            't': None,
            'stNum': None,
            'sqNum': None,
            'simulation': None,
            'confRev': None,
            'ndsCom': None,
            'numDatSetEntries': None
        }

        tag_handlers = {
            '80': ('gocbRef', lambda x: bytes.fromhex(''.join(x)).decode('ascii', errors='replace')),
            '81': ('timeAllowedToLive', lambda x: int(''.join(x), 16)),
            '82': ('datSet', lambda x: bytes.fromhex(''.join(x)).decode('ascii', errors='replace')),
            '83': ('goID', lambda x: bytes.fromhex(''.join(x)).decode('ascii', errors='replace')),
            '84': ('t', lambda x: GooseParser.parse_goose_time(x)),
            '85': ('stNum', lambda x: int(''.join(x), 16)),
            '86': ('sqNum', lambda x: int(''.join(x), 16)),
            '87': ('simulation', lambda x: bool(int(x[0], 16))),
            '88': ('confRev', lambda x: int(''.join(x), 16)),
            '89': ('ndsCom', lambda x: bool(int(x[0], 16))),
            '8a': ('numDatSetEntries', lambda x: int(''.join(x), 16))
        }

        while i < len(pdu):
            tag = pdu[i]

            if tag in tag_handlers and i + 1 < len(pdu):
                field_name, handler = tag_handlers[tag]
                length = int(pdu[i + 1], 16)

                if i + 2 + length <= len(pdu):
                    data = pdu[i + 2:i + 2 + length]
                    try:
                        result[field_name] = handler(data)
                    except (ValueError, IndexError) as e:
                        print(f"Error processing tag {tag}: {e}")

                i += 2 + length
                if tag == '8a':  # Последний ожидаемый тег
                    break
            else:
                i += 1

        self.all_data = pdu[i:]
        return result

    def parse_goose_all_data(self):
        """
        Парсинг блока allData из GOOSE PDU
        :param pdu_hex: Список hex-байтов (например, ['ab', '82', '00', 'dc', ...])
        :return: Список словарей с распарсенными данными
        """
        pdu_hex = self.all_data
        i = 0
        data_entries = []

        while i < len(pdu_hex):
            # Ищем начало allData (0xAB)
            if pdu_hex[i] == 'ab' and i + 3 < len(pdu_hex):
                # Пропускаем заголовок allData (ab 82 00 dc)
                i += 4
                continue

            # Обработка DataEntry (0xA2)
            if pdu_hex[i] == 'a2' and i + 1 < len(pdu_hex):
                entry_length = int(pdu_hex[i + 1], 16)
                entry_data = pdu_hex[i + 2:i + 2 + entry_length]

                data_ref = None
                value = None
                timestamp = None
                j = 0

                # Парсим содержимое DataEntry
                while j < len(entry_data):
                    tag = entry_data[j]

                    # DataRef (0x83)
                    if tag == '83' and j + 2 < len(entry_data):
                        length = int(entry_data[j + 1], 16)
                        data_ref = int(entry_data[j + 2], 16)
                        j += 2 + length

                    # Value (0x84)
                    elif tag == '84' and j + 1 < len(entry_data):
                        length = int(entry_data[j + 1], 16)
                        value = entry_data[j + 2:j + 2 + length]
                        value = ''.join(value)  # Если value - это список строк, объединяем их в одну строку
                        value = bytes.fromhex(value)
                        value = ''.join(format(byte, '08b') for byte in value)
                        j += 2 + length

                    # Timestamp (0x91)
                    elif tag == '91' and j + 9 < len(entry_data):
                        length = int(entry_data[j + 1], 16)
                        if length == 8:
                            time_bytes = entry_data[j + 2:j + 10]
                            seconds = int.from_bytes(bytes.fromhex(''.join(time_bytes[:4])), 'big')
                            nanos = int.from_bytes(bytes.fromhex(''.join(time_bytes[4:])), 'big')
                            timestamp = datetime.fromtimestamp(seconds + nanos / 1e9, tz=timezone.utc)
                        j += 2 + length

                    else:
                        j += 1

                # Добавляем распарсенную запись
                data_entries.append({
                    'Boolean 11_1': bool(data_ref),
                    'Boolean 11_2': None,
                    'UTC Time 11_3': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if timestamp else None
                })

                i += 2 + entry_length
            else:
                i += 1

        return data_entries

def packet_handler(pkt):
    if pkt.haslayer('Ether') and pkt.type == 0x88B8:  # Проверяем GOOSE
        # Формируем вывод
        print("\n" + "=" * 50)
        print("=== НАЙДЕН НОВЫЙ GOOSE-КАДР ===")
        print("=" * 50)

        # Преобразуем сырые байты в hex с пробелами
        hex_bytes = ' '.join(f"{b:02x}" for b in pkt.original)

        # Выводим с разбивкой по 16 байт в строке
        for i in range(0, len(hex_bytes.split()), 16):
            print(' '.join(hex_bytes.split()[i:i + 16]))

        print("=" * 50 + "\n")
        cadr = hex_bytes
        res = GooseParser(cadr)
        frame = res.parse_goose_frame()
        print("Разобранный кадр:")
        width = len(max(frame.keys(), key=len)) if frame else 0
        for k, v in frame.items():
            if k == 'pdu':
                continue
            print(f'{k.ljust(width + 1)}: {v}')

        print('=' * 60)

        pdu = res.parse_goose_pdu()
        if pdu:
            width = len(max(pdu.keys(), key=len))
            for k, v in pdu.items():
                print(f'{k.ljust(width + 1)}: {v}')
        else:
            print("Не удалось разобрать PDU")

        print('=' * 60)

        try:
            data = res.parse_goose_all_data()
            if data:
                pprint(data)
            else:
                print("Не удалось разобрать AllData")
        except Exception as e:
            print(f"Ошибка при парсинге AllData: {str(e)}")
        time.sleep(0.01)

sniff(prn=packet_handler, filter="ether proto 0x88B8", store=0)

