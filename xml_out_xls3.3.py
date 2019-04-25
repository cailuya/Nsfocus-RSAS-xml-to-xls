import sys
from bs4 import BeautifulSoup
import time
import xlwt
from os.path import splitext
# 第四版
# 计划，把三个表合在一起，数据结构优化 ok
# data 数据结构 [表名,标题,列宽,[row1,row2...]] ok
# 函数式化改造 部分完成
# 3.1输出名为 xml 内的名
# 3.3修正 bug，端口输出异常

def vuln(xml):
    "输出漏洞信息，返回 data 为二维数组"
    print("开始生成漏洞汇总表数据")
    targets = xml.data.report.targets.find_all('target')
    data = []
    for target in targets:

        def vuln_dict(target):
            "组装漏洞字典，返回字典"
            def risk_level(risk_points):
                "用于判断漏洞危险等级"
                risk_points = float(risk_points)
                if risk_points < 4.0:
                    risk_level = "低"
                elif 4.0<=risk_points and risk_points<7.0:
                    risk_level = "中"
                else :
                    risk_level = "高"
                return risk_level

            def vuln_detail(vuln_detail):
                "返回漏铜详细信息"
                vuln_detail_r = [vuln_detail.find('vul_id').get_text(),[
                    vuln_detail.find('name').get_text(),
                    vuln_detail.find('threat_category').get_text(),
                    risk_level(vuln_detail.find('risk_points').get_text()),
                    vuln_detail.find('risk_points').get_text(),
                    vuln_detail.find('solution').get_text(),
                    vuln_detail.find('description').get_text()
                    ]]
                return vuln_detail_r

            vuln_dict = {}
            for a in list(map(vuln_detail,target.vuln_detail.find_all('vuln'))):
                vuln_dict[a[0]]=a[1]
            return vuln_dict

        vuln_dict = vuln_dict(target)
        for vuln in target.vuln_scanned.find_all('vuln'):
            row = [
            target.ip.get_text(),vuln.find('port').get_text(),
            vuln.find('protocol').get_text(),
            vuln.find('service').get_text()
            ]
            vul_id = vuln.find('vul_id').get_text()
            vuln_detail =  vuln_dict[vul_id]
            row.extend(vuln_detail)
            data.append(row)
    # def target_vuln(target):
    #     def row(vuln):
    #         row = [
    #         target.ip.get_text(),vuln.find('port').get_text(),
    #         vuln.find('protocol').get_text(),
    #         vuln.find('service').get_text()
    #         ]
    #         pass
    #     pass
    name = "漏洞汇总"
    title_width = [4000,1500,2000,2000,6000,3000,2000,2000,10000,10000]
    titles = ["IP地址","端口","协议","应用程序","漏洞名","漏洞类别","风险等级","风险值","漏洞描述","解决办法"]
    return_data = [name,titles,title_width,data]
    print("OK")
    return return_data


def ip(xml):
    "输出 ip"
    print("开始生成存活IP汇总表数据")
    targets = xml.data.report.targets.find_all('target')
    data = []
    for target in targets:
        row = [target.ip.get_text(),'']
        data.append(row)
    titles = ['IP地址','']
    name = '存活IP汇总'
    title_width = [4000,4000]
    return_data = [name,titles,title_width,data]
    print("OK")
    return return_data

def port(xml):
    "输出端口信息，返回 data 为二维数组"
    print("开始生成端口数据")
    targets = xml.data.report.targets.find_all('target')
    data = []
    for target in targets:
        try:
            info = target.appendix_info.info
            record_results = info.find_all('record_results')
        except AttributeError as E:
            row = [target.ip.get_text(),"未检测到开放端口"]
            data.append(row)
        else:
            info = target.appendix_info.find('info')
            record_results = info.find_all('record_results')
            record_results = record_results[:-1]

            for record_result in record_results:
                row = [target.ip.get_text()]
                for value in record_result.find_all('value'):
                    row.append(value.get_text())
                data.append(row)
    titles = ['IP地址','端口','协议','服务','开放状态']
    name = '端口信息'
    title_width = [4000,4000,4000,4000,4000]
    return_data = [name,titles,title_width,data]
    print("OK")
    return return_data


def write_xls(out_file_name,*datas):
    "写入 xls 文件"
    xls = xlwt.Workbook()
    print("开始写入 xls 文件")
    # print(datas)
    for data in datas:
        table = xls.add_sheet(data[0])
        x = 0
        for title in data[1]:
            table.write(0,x,title)
            x += 1
        y = 1
        for row in data[3]:
            x=0
            for value in row:
                table.write(y,x,value)
                x +=1
            y+=1
        i = 0
        for title_w in data[2]:
            table.col(i).width = title_w
            i+=1
    xls.save(out_file_name)
    print("写入完成")



def xml_init(input_file):
    "初始化 xml 文件，返回 bsObj 对象"
    try:
        xml = open(input_file,'r')
        bsObj = BeautifulSoup(xml,"lxml-xml")
        print("XML 对象初始化完成")
    except FileNotFoundError :
        print('未找到文件')
    return bsObj

def file_name(xml):
    file_name = xml.data.report.task.find('name').get_text()
    return file_name


def main():
    try:
        print("开始操作，文件名：",sys.argv[1])
        input_file = sys.argv[1]
        xml = xml_init(input_file)
        # write_xls(file_name(xml)+'_'+splitext(input_file)[0]+'_ip.xls',ip(xml))
        # write_xls(file_name(xml)+'_'+splitext(input_file)[0]+'_vuln.xls',vuln(xml))
        # write_xls(file_name(xml)+'_'+splitext(input_file)[0]+'_port.xls',port(xml))
        write_xls(file_name(xml)+'_IP存活表.xls',ip(xml))
        write_xls(file_name(xml)+'_漏洞汇总.xls',vuln(xml))
        write_xls(file_name(xml)+'_端口开放情况.xls',port(xml))
    except IndexError as E:
        #help
        print(E)


main()