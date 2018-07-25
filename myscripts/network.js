/* June, 2018
 * Tommy Dang (on the Scagnostics project, as Assistant professor, iDVL@TTU)
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, THE AUTHORS MAKE NO REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

//var colorNetwork = d3.scale.category10();
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


var  svgNetwork = d3.select("#networkPanel")
    .append("svg")
    .attr("width", height+100)
    .attr("height",height);

var nodes=[], links=[];

var force = d3.layout.force()
    .gravity(0.18)
    .distance(50)
    .charge(-70)
    .size([height+140, height]);
 


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
   return  2+ Math.pow(d.data.length,0.4);
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
            var indexL = isContainedName(links, link.name);
            if (indexL < 0) {
                link.count = 1;
                links.push(link);
            }
            else
                links[indexL].count++;
        }

    });
}


function drawNetwork() {
    svgNetwork.selectAll("*").remove();
    let maxLinkCount = d3.max(links.map(d=>1+Math.pow(d.count-1,0.5)));
    let forceStrengthScale = d3.scale.linear().domain([0, maxLinkCount]).range([0.2, 0.8]);



    // Filet by Link count *****************
    links = links.filter(function (l) {
        return l.count>=5;
    });
    //Filter by visibleGroups
    //if(viewing by description) then don't draw the network at all
    let viewOptions = termSelector.getViewOptions();
    if(_.contains(viewOptions, 'description')){
        return;
    }
    // Remove SINGLE nodes  **************************************************
    var str =" "
    for (var i=0; i< links.length;i++){
        var id1 = links[i].source.name;
        if (str.indexOf(" "+id1+" ") <0 )
            str+=id1 +" ";
        var id2 = links[i].target.name;
        if (str.indexOf(" "+id2+" ") <0 )
            str+=id2 +" ";
    }

    nodes = nodes.filter(function(d){
        return str.indexOf(" "+d.name+" ")>=0;
    })

    //Filter the nodes which are not in the visible options
    let filteredNodes = nodes.filter(n=>_.contains(viewOptions, n.type));
    let filteredLinks = links.filter(l=>_.contains(viewOptions, l.source.type) && _.contains(viewOptions, l.target.type));
    debugger
    //Filter the links which are not in the visible options

    force
        .nodes(filteredNodes)
        .links(filteredLinks)
        .linkStrength((d)=>{
            if(!d.count) d.count = 0;
            let linkForceStrength = forceStrengthScale(d.count);
            return linkForceStrength;
        })
        .start();

    var link = svgNetwork.selectAll(".link")
        .data(filteredLinks)
        .enter().append("line")
        .attr("class", "link")
        .attr('stroke-width', function(d){
            return 0+Math.pow(d.count-1,0.3);
        })
        .attr('stroke-opacity', 0.5)
        .attr('stroke', function (d) {
            if (d.source.type == d.target.type)
                return colorNetwork(d.source.type)
            else    
                return "#000";
        });    

    var node = svgNetwork.selectAll(".node")
        .data(filteredNodes)
        .enter().append("g")
        .attr("class", "node")
        .call(force.drag);
    node.append('circle')
        .attr('r', getNodeSize)
        .attr('fill', function (d) {
            return colorNetwork(d.type);
        })
        .attr('stroke-width', 0.5)
        .attr('stroke-opacity', 0.9)
        .attr('stroke', "#fff");

    node.append("title")
        .text(function (d) { return d.name; });

    
    node.append("text")
        .attr("dx", 0)
        .attr("dy", function (d) {
              return  -getNodeSize(d)-2;
        })
        .style("text-anchor","middle")
        .style("text-shadow", "1px 1px 0 rgba(255, 255, 255, 0.6")
        //.style("font-weight", function(d) { return d.isSearchTerm ? "bold" : ""; })
        .attr("font-family", "sans-serif")
        .attr("font-size", function(d) {
          return 8+ getNodeSize(d)/1.7;
        })
        .text(function (d) {
            return d.name
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