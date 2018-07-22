/* June, 2018
 * Tommy Dang (on the Scagnostics project, as Assistant professor, iDVL@TTU)
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, THE AUTHORS MAKE NO REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

var colorNetwork = d3.scale.category10();
//function colorNetwork(n) {
//    var colores_g = ["#3060aa", "#f80", "#f00", "#10aa18", "#990099", "#0099c6", "#dd4477", "#66aa00", "#b82e2e", "#316395", "#994499", "#22aa99", "#aaaa11", "#6633cc", "#e67300", "#8b0707", "#651067", "#329262", "#5574a6", "#3b3eac"];
//    return colores_g[n % colores_g.length];
//}


var  svgNetwork = d3.select("#networkPanel")
    .append("svg")
    .attr("width", height)
    .attr("height",height);

var nodes=[], links=[];

var force = d3.layout.force()
    .gravity(0.1)
    .distance(40)
    .charge(-23)
    .size([height, height]);
 


 // check if a node for  already exist.
function isContainedName(a, name) {
    if (a){
        for (var i=0; i<a.length;i++){
            if (a[i].name==name)
                return i;
        }
    }
    return -1;
}
function getNodeSize(d) {
   return  2+ Math.pow(d.data.length,0.3);
}

function processNetwork(data_) {
    var networkData = undefined;
    if (data_==undefined)
        networkData = data;
    else{
        nodes=[], links=[];
        networkData = data_;
    }

    networkData.forEach(function (d) {
        // create new dimensions for data
        d.vendorNode = {};

        // Process vendors *******************************************************************
        var listPreNodes1 = [];
        if (d.cve.affects.vendor.vendor_data && d.cve.affects.vendor.vendor_data.length > 0) {
            // if (d.cve.affects.vendor.vendor_data.length>1){//  && .cve.affects.vendor.vendor_data.length>2;})){
            for (var k = 0; k < d.cve.affects.vendor.vendor_data.length; k++) {
                var item = d.cve.affects.vendor.vendor_data[k];
                var name = item.vendor_name;

                var index = isContainedName(nodes, name);
                var obj = {};
                if (index < 0) {
                    obj.name = name;
                    obj.type = "vendor";
                    obj.data = [];   // List of cves
                    obj.data.push(d);

                    obj.product = item.product;
                    nodes.push(obj);
                }
                else {
                    nodes[index].data.push(d);
                    obj = nodes[index];
                }
                // create new dimensions for data
                if (k == 0)  // only get the first vendor
                    d.vendorNode = obj;

                // Links
                for (var q = 0; q < listPreNodes1.length; q++) {
                    var node2 = listPreNodes1[q];
                    var link = {};
                    link.source = obj;
                    link.target = node2;
                    link.name = obj.name + "_" + node2.name;
                    var indexL = isContainedName(links, link.name);
                    if (indexL < 0) {
                        link.count = 1;
                        links.push(link);
                    }
                    else {
                        links[indexL].count++;
                    }

                }
                listPreNodes1.push(obj);


                // Process products *******************************************************************
                if (item.product && item.product.product_data) {
                    for (var q = 0; q < item.product.product_data.length; q++) {
                        var e = item.product.product_data[q];
                        var name = e.product_name;

                        var index = isContainedName(nodes, name);
                        var obj2 = {};
                        if (index < 0) {
                            obj2.name = name;
                            obj2.type = "product";
                            obj2.data = [];   // List of cves
                            obj2.data.push(d);
                            nodes.push(obj2);
                        }
                        else {
                            nodes[index].data.push(d);
                            obj2 = nodes[index];
                        }

                        // create new dimensions for data
                        if (k == 0)  // only get the first vendor
                            d.productNode = obj2;

                        // Links vendor to product ***********************
                        var link = {};
                        link.source = obj;
                        link.target = obj2;
                        link.name = obj.name + "_" + obj2.name;
                        var indexL = isContainedName(links, link.name);
                        if (indexL < 0) {
                            link.count = 1;
                            links.push(link);
                        }
                        else
                            links[indexL].count++;
                    }
                }
            }
        }


        // Process vulnerability types *******************************************************************
        var listPreNodes2 = [];
        if (d.cve.problemtype.problemtype_data && d.cve.problemtype.problemtype_data[0].description.length > 0) {//  && .cve.affects.vendor.vendor_data.length>2;})){
            for (var k = 0; k < d.cve.problemtype.problemtype_data[0].description.length; k++) {
                var item = d.cve.problemtype.problemtype_data[0].description[k];
                var name = item.value;

                var index = isContainedName(nodes, name);
                var obj = {};
                if (index < 0) {
                    obj.name = name;
                    obj.lang = item.lang;  // language
                    obj.type = "vulnerability_type";
                    obj.data = [];   // List of cves
                    obj.data.push(d);
                    nodes.push(obj);
                }
                else {
                    nodes[index].data.push(d);
                    obj = nodes[index];
                }
                // create new dimensions for data
                if (k == 0)  // only get the first vulnerability type
                    d.problemNode = obj;


                for (var q = 0; q < listPreNodes2.length; q++) {
                    var node2 = listPreNodes2[q];
                    var link = {};
                    link.source = obj;
                    link.target = node2;
                    link.name = obj.name + "_" + node2.name;
                    var indexL = isContainedName(links, link.name);
                    if (indexL < 0) {
                        link.count = 1;
                        links.push(link);
                    }
                    else {
                        links[indexL].count++;
                    }
                }
                listPreNodes2.push(obj);
            }
        }

        // Link between vendors and vulnerability types *******************************************************************
        if (listPreNodes1.length > 0 && listPreNodes2.length > 0) {
            var link = {};
            link.source = listPreNodes1[0];
            link.target = listPreNodes2[0];
            link.name = listPreNodes1[0].name + "_" + listPreNodes2[0].name;
               links.push(link);
        }
    });
}


function drawNetwork() {
    svgNetwork.selectAll("*").remove();

    force
        .nodes(nodes)
        .links(links)
        .start();

    var link = svgNetwork.selectAll(".link")
        .data(links)
        .enter().append("line")
        .attr("class", "link")
        .attr('stroke-width', function(d){
            return 0.5+Math.sqrt(d.count-1);
        })
        .attr('stroke-opacity', 0.5)
        .attr('stroke', function (d) {
            if (d.source.type == d.target.type)
                return colorNetwork(d.source.type)
            else    
                return "#000";
        });    

    var node = svgNetwork.selectAll(".node")
        .data(nodes)
        .enter().append("g")
        .attr("class", "node")
        .call(force.drag);
    node.append('circle')
        .attr('r', getNodeSize)
        .attr('fill', function (d) {
            return colorNetwork(d.type);
        })
        .attr('stroke-width', 0.5)
        .attr('stroke-opacity', 0.75)
        .attr('stroke', "#fff");

    node.append("title")
        .text(function (d) { return d.name; });

    
    node.append("text")
        .attr("dx", -18)
        .attr("dy", 8)
        .style("font-family", "overwatch")
        .style("font-size", "18px")

        .text(function (d) {
            return "";//d.name
        });

    force.on("tick", function () {
        link.attr("x1", function (d) {
            return d.source.x;
        })
            .attr("y1", function (d) {
                return d.source.y;
            })
            .attr("x2", function (d) {
                return d.target.x;
            })
            .attr("y2", function (d) {
                return d.target.y;
            });
        node.attr("transform", function (d) {
            return "translate(" + d.x + "," + d.y + ")";
        });
    });


}