import winreg
import csv

def get_software(hive, flag):
    aReg = winreg.ConnectRegistry(None, hive)
    aKey = winreg.OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                          0, winreg.KEY_READ | flag)

    count_subkey = winreg.QueryInfoKey(aKey)[0]

    software_list = []

    for i in range(count_subkey):
        software = {}
        try:
            asubkey_name = winreg.EnumKey(aKey, i)
            asubkey = winreg.OpenKey(aKey, asubkey_name)
            software['name'] = winreg.QueryValueEx(asubkey, "DisplayName")[0]

            try:
                software['version'] = winreg.QueryValueEx(
                    asubkey, "DisplayVersion")[0]
            except EnvironmentError:
                software['version'] = 'undefined'
            try:
                software['publisher'] = winreg.QueryValueEx(
                    asubkey, "Publisher")[0]
            except EnvironmentError:
                software['publisher'] = 'undefined'
            software_list.append(software)
        except EnvironmentError:
            continue

    return software_list


software_list = get_software(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY) + get_software(
    winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY) + get_software(winreg.HKEY_CURRENT_USER, 0)


# field names
header = ['Name', 'Version', 'Publisher']

# name of csv file
filename = "installed_software.csv"

# writing to csv file
with open(filename, 'w') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(header)

    for software in software_list:
        csvwriter.writerow(
            [software['name'], software['version'], software['publisher']])
