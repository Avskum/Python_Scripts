import pymysql.cursors
import shutil
import os

## db connection
connection = pymysql.connect(host='localhost',
                             user='root',
                             password='pwd',
                             db='system_mail',
                             cursorclass=pymysql.cursors.DictCursor)
 ## select from table and row datas
cursor = connection.cursor()
sql="SELECT id, name, state FROM domain WHERE state='2'"
cursor.execute(sql)
records = cursor.fetchall()
print("Total number of records for deleting is: ", cursor.rowcount)

cursor.execute("select distinct name from domain where state = 2")
deleted = set(row['name'] for row in cursor.fetchall())

cursor.execute("select distinct name from domain where state != 2")
active = set(row['name'] for row in cursor.fetchall())

#delete not needed datas
to_delete = deleted - active

print('Printing each domain record', "\n")
for row in records:

    print("id = ", row["id"], )
    print("name = ", row["name"])
    print("state  = ", row["state"], "\n")

    id = row["id"]
    name = row["name"]
    state = row["state"]

    #delete file according to fileter and selected ID from table
    if to_delete:
        try:
            if os.path.exists('/data/sa/' + name):
                print('found records for deleting: ' + name, "\n")
                print("Total number of records for deleting is: ", cursor.rowcount)
                input("Press Enter to continue...")
                shutil.rmtree('/data/sa/' + name)
                print('records deleted')            
            else:
                print('no Directory found')
        except Exception as error:
            print("Directory already deleted or never existed")
    else:
        print('no records for deleting found')
        print('domain', name)
        print('hasnt state', state, "\n")

quit()
connection.close()
