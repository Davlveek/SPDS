# SPDS
Запуск системы: ```python spds.py <file for analysis>```

## Разворачивание системы
### Хост
* Установить IDA Pro и добавить ее папку в переменную PATH
* Установить VirtualBox

### ВМ для DynamoRIO
Используется ОС Windows
1. Поместить [DynamoRIO](https://github.com/DynamoRIO/dynamorio/wiki/Downloads) в удобное место на машине
2. Поместить файлы проекта SPDS в папку с DynamoRIO
3. Установить Python 3.8.2
4. Запустить агента для DynamoRIO: ```python dynagent.py```
5. Сделать снэпшот текущего состояния

### ВМ для Cuckoo Sandbox
Используется Ubuntu 18.04 LTS
1. Установить [Cuckoo Sandbox](https://cuckoosandbox.org/)
2. Поместить папку проекта SPDS в удобное место на машине
3. Запустить агента для Cuckoo Sandbox: ```sudo python3 cuckagent.py```
4. Сделать снэпшот текущего состояния

### Конфигурационный файл
В конфигурационный файл (*management\config.json*) записать адреса используемых ВМ, их имена и необходимые для них снэпшоты.