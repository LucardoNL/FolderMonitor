from winevt import EventLog
from dateutil import parser, tz
import datetime
import csv
import os

apppath = os.path.dirname(os.path.abspath(__file__))

events = {}
mapcount = []


def main():
    query = EventLog.Query("Security", "Event/System[EventID=4663]")
    checklist = []
    indexcounter = 0
    comparePath = ''
    donttracklist = []  # 'OUTLOOK.EXE', 'BoxSync.exe']
    for event in query:
        DateTime, eventID, User, Path, Program, Handle = eventparser(event)
        if Handle not in checklist and datetime.datetime.strptime(DateTime, "%Y-%m-%d %H:%M:%S.%f") > (
                    datetime.datetime.now() - datetime.timedelta(
                    minutes=10)) and not any(prog in Program for prog in donttracklist) and Path != comparePath:
            checklist.append(DateTime)
            checklist.append(Handle)
            #writeevent(indexcounter, DateTime, eventID, User, Path, Program)
            pathanalyser(comparePath, Path, Program, DateTime)
            indexcounter += 1
            comparePath = Path

        else:
            pass

    with open(os.path.dirname(os.path.abspath(__file__))+"\\output.csv", 'a', newline="") as f: #Hoe gaan we hier slim met PAD om?
        writer = csv.writer(f)
        writer.writerows(mapcount)
        # for id, body in events.items():
        #    print(id, body)


def eventparser(event):
    DateTime = str(parser.parse(event.System.TimeCreated['SystemTime']).astimezone(tz.tzlocal()))[:22]
    eventID = event.System.EventRecordID.cdata
    User = event.EventData.Data[1].cdata
    Path = event.EventData.Data[6].cdata
    Program = event.EventData.Data[11].cdata
    Handle = event.EventData.Data[7].cdata
    return DateTime, eventID, User, Path, Program, Handle


def writeevent(indexcounter, DateTime, eventID, User, Path, Program):
    events[indexcounter] = {}
    events[indexcounter]['ID'] = eventID
    events[indexcounter]['DateTime'] = DateTime
    events[indexcounter]['User'] = User
    events[indexcounter]['Path'] = Path
    events[indexcounter]['Program'] = Program


def pathanalyser(comparePath, Path, Program, DateTime):
    pathitem = Path.split('\\')[-1]
    if comparePath is '':
        comparePath = 'root'
    prevpathitem = comparePath.split('\\')[-1]
    program = Program.split('\\')[-1]
    analysedpath = []
    analysedpath.extend((pathitem, prevpathitem, program, 1, DateTime))
    if analysedpath not in mapcount:
        mapcount.append(analysedpath)
    else:
        for item in mapcount:
            if analysedpath == item:
                item[3] += 1


                # Runs the program.


if __name__ == '__main__':
    main()
