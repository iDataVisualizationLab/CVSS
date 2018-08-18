var fileName;
let year = 2017;
//fileName = document.getElementById("datasetsSelect").value;
// fileName = "nvdcve-1.0-2014";
// fileName = "nvdcve-1.0-2015";
// fileName = "nvdcve-1.0-2016";
// fileName = "nvdcve-1.0-2017";
fileName = "isp1";
// fileName = "nvdcve-1.0-2018-1";
// fileName = "nvdcve-1.0-2018";
fileName = "allCVEs";
// fileName = "../data/" + fileName + ".json";
d3.json(fileName, (error, raw_data)=>{
    if(raw_data.CVE_Items){
        raw_data = raw_data.CVE_Items;
    }
    data = raw_data;
    cves = data;
    loadCloudCVEs(["vendor", "product", "vulnerability_type"], draw);

});
function colorNetwork(type) {
    var colores_g = ["#00a","#990099", "#854", "#000"];
    if (type=="vendor")
        return colores_g[0];
    else if (type=="product")
        return colores_g[1];
    else if (type=="vulnerability_type")
        return colores_g[2];
    else
        return colores_g[3];

}
var colors = {
    "CRITICAL": [0, 100, 50],
    "HIGH": [35, 100, 50],
    "MEDIUM": [60, 100, 39],
    "LOW": [120, 100, 45],
    "NONE": [0, 0, 0]
};