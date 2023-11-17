# INT-4 test task
Тестовое задание в отдел INT-4
"Отдел обнаружения вредоносного ПО. ESC" в рамках 2-го этапа стажировки
2023.2 PT-START Intensive.

Задание выполнено на основе данного [технического задания](https://sadykov.notion.site/INT-4-5e842292653b435193c2c0cb80d1d99c). 
В соответствии с ним имеются модули:
- импорта `collector.py` - собирает и парсит данные из источников
- совмещения данных `combiner.py` - маппит данные и убирает повторы
- аналитики `analyzer.py` - выставляет уровень угрозы
- экспорта `exporter.py` - преобразует фиды в формат JSONL и выводит

Корневой сущностью всей программы является модель фида, описанная в файле `feed.py`.

## Built with
- [pydantic](https://github.com/pydantic/pydantic), [pydantic-settings](https://github.com/pydantic/pydantic-settings) -
библиотеки для декларативного описания моделей конфигурационного файла и сущности `Feed`, а также
для валидации данных
- [pyyaml](https://github.com/yaml/pyyaml) - библиотека для парсинга yaml файлов
- [logging](https://docs.python.org/3/howto/logging.html) - встроенная библиотека для логирования
- [vt-py](https://github.com/VirusTotal/vt-py) - клиент для работы с API VirusTotal
- [requests](https://github.com/psf/requests) - библиотека для работы с http запросами
- [pyquery](https://github.com/gawel/pyquery) - библиотека на базе быстрого парсера lxml с поддержкой jquery запросов

## Requirements
Скрипт тестировался на версиях Python 3.10+. Список необходимых зависимостей указан в файле `requirements.txt`.

## Getting Started
В папке `config` необходимо сконфигурировать файл `config.yaml`. В нем необходимо вставить свой API ключ в поле `api`,
вложенное в поле `virustotal`. Также опционально можно изменить параметры логера, которые вложены в поле `logger`.

**Важно**: остальные значения менять **не нужно**, так как они уже сконфигурированы для корректной работы маппинга 
и программы в целом в соответствии с техническим заданием.

После конфигурирования скрипт можно **запустить** при помощи команды:
```bash
make
```

Вот так можно **очистить** созданные виртуальным окружением питона файлы и кэши:
```bash
make clean
```

## Decisions
### Threat level
Было принято решение ввести 4 уровня угрозы (поле `definition` внутри поля `threat_level` в конфигурационном файле)
и соответствующие им численные значения (больше - выше уровень угрозы):
- UNDETECTED (0)
- LOW (1)
- MEDIUM (2)
- HIGH (3)

Затем каждому классу ВПО из соответствующего файла технического задания был присвоен уровень угрозы от 1 до 3 
(поле `mapping` внутри поля `threat_level` в конфигурационном файле) по такому принципу:
- если класс сам по себе не является вредоносным ПО - **первый** уровень, например, RemoteAdmin
- если класс направлен на спам с целью вывести из строя, либо подловить на невнимательности или принудить к необдуманным
действиям из-за причиненных неудобств - **второй** уровень, например, DoS, Hoax, Flooder
- если класс является вредоносным ПО, которое крадет конфиденциальную информацию, вымогает, может работать скрытно и/или
само распространяется, либо является составной частью такого ПО - **третий** уровень, например, любой Trojan, Virus, Worm

Уровень угрозы **UNDETECTED** был введен для случаев, когда отсутствуют детекты на VirusTotal и APT ETDA, либо когда APT
ETDA не дал результатов, а на VirusTotal несколько детектов, которых ему недостаточно для вердикта. Обычно такое происходит
с самыми свежими образами на MalwareBazaar.

Итоговый уровень угрозы в поле `threat_level` фида выставляется как максимальный из всех встретившихся уровней угроз 
классов ВПО поля `malware_class`. Например, имеем значение поля `malware_class = ['Hoax', 'RemoteAdmin']`, то есть уровень
угрозы у `Hoax` равен `2`, а у `RemoteAdmin` равен `1`. Значит, `threat_level = MEDUIM`.

### Модуль импорта
1. С сайта [MalwareBazaar](https://bazaar.abuse.ch/) собирается информация о последних 100 загруженных образцах, а именно:
    - `md5`
    - `sha256`
    - `signature` в поле `malware_family`
2. Если сигнатура из предыдущего шага пустая, то этот шаг пропускается, иначе на сайте [APT ETDA](https://apt.etda.or.th/cgi-bin/aptgroups.cgi)
происходит поиск сигнатуры в категории `Malware`. Если в результатах поиска обнаруживается сигнатура, то открывается страница
с ее описанием, откуда берутся значения типов в поле `malware_class`, которые будут перемаплены в классы ВПО в модуле совмещения данных.
3. С использованием API [VirusTotal](https://www.virustotal.com) достаются детекты в поле `av_detects`, а также значения
для полей `malware_family` и `malware_class`, которые будут перемаплены в классы ВПО в модуле совмещения данных.

### Модуль совмещения данных
1. В поле `malware_class` происходит перемапливание всех значений, полученных с VirusTotal и APT ETDA. Затем удаляются
повторяющиеся. Также удаляются более общие значения, например, `Trojan`, если присутствует более точное, скажем, `Trojan-PSW`.
2. Из полей `malware_family` и `av_detects` удаляются повторяющиеся значения.

В **модуле аналитики** для каждого фида задается поле `threat_level` в соответствии с вышеописанной логикой. И наконец, в **модуле экспорта** происходит вывод фидов в формате JSONL.

## Additional Information
В папке `logs` находится файл `main.log` - пример файла лога, сконфигурированного настройками из файла `config.yaml`.