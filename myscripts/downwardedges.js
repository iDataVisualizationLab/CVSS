/* June, 2018
 * Tommy Dang (on the Scagnostics project, as Assistant professor, iDVL@TTU)
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, THE AUTHORS MAKE NO REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

var widthN = 600,
    heightN = 600;

var  svgNetwork = d3.select("#networkPanel")
    .append("svg")
    .attr("width", widthN)
    .attr("height",heightN);

var nodesN, linksN;

var force = d3.layout.force()
    .gravity(0.1)
    .distance(10)
    .charge(-40)
    .size([widthN, heightN]);
 

function colaNetwork(nodes, links){
    nodesN = nodes;
    linksN = links;
 //   svgNetwork.selectAll("*").remove();

    force
        .nodes(nodes)
        .links(links)
        .start();

    var link = svg.selectAll(".link")
        .data(links)
        .enter().append("line")
        .attr("class", "link");

    var node = svgNetwork.selectAll(".node")
        .data(nodes)
        .enter().append("g")
        .attr("class", "node")
        .call(force.drag);
    node.append('circle')
        .attr('r', 5)
        .attr('fill', function (d) {
            return color(d.group);
        });

   /* node.append("text")
        .attr("dx", -18)
        .attr("dy", 8)
        .style("font-family", "overwatch")
        .style("font-size", "18px")

        .text(function (d) {
            return d.name
        });*/

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