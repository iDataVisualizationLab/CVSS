// Parallel Coordinates
// Copyright (c) 2012, Kai Chang
// Released under the BSD License: http://opensource.org/licenses/BSD-3-Clause

// var width = document.body.clientWidth;
var width = 1770;
var height = 600;

var m = [35, 0, 10, height],
    w = width,
    h = height - m[0] - m[2],
    xscale = d3.scale.ordinal().rangePoints([0, w], 1),
    yscale = {},
    dragging = {},
    line = d3.svg.line(),
    axis = d3.svg.axis().orient("left").ticks(1 + height / 50),
    data,
    foreground,
    background,
    highlighted,
    dimensions,
    legend,
    render_speed = 2,
    brush_count = 0,
    excluded_groups = [];

var colors = {
    "CRITICAL": [0, 100, 50],
    "HIGH": [35, 100, 50],
    "MEDIUM": [60, 100, 39],
    "LOW": [120, 100, 45],
    "NONE": [0, 0, 0]
};

function rgbToHsl(r, g, b) {
    r /= 255, g /= 255, b /= 255;

    var max = Math.max(r, g, b), min = Math.min(r, g, b);
    var h, s, l = (max + min) / 2;

    if (max == min) {
        h = s = 0; // achromatic
    } else {
        var d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);

        switch (max) {
            case r:
                h = (g - b) / d + (g < b ? 6 : 0);
                break;
            case g:
                h = (b - r) / d + 2;
                break;
            case b:
                h = (r - g) / d + 4;
                break;
        }

        h /= 6;
    }

    return [h, s, l];
}

// Scale chart and canvas 
d3.select("#chart")
    .style("height", (h + m[0] + m[2]) + "px")

d3.selectAll("canvas")
    .attr("width", w)
    .attr("height", h)
    .style("padding", m.slice(0, 3).join("px ") + "0px");


// Foreground canvas for primary view
foreground = document.getElementById('foreground').getContext('2d');
foreground.globalCompositeOperation = "destination-over";
foreground.strokeStyle = "rgba(0,100,160,0.1)";
foreground.lineWidth = 0.5;
foreground.fillText("Loading...", w / 2, h / 2);

// Highlight canvas for temporary interactions
highlighted = document.getElementById('highlight').getContext('2d');
highlighted.strokeStyle = "rgba(0,100,160,1)";
highlighted.lineWidth = 4;

// Background canvas
background = document.getElementById('background').getContext('2d');
background.strokeStyle = "rgba(0,100,160,0.1)";
background.lineWidth = 1;

// SVG for ticks, labels, and interactions
var svg = d3.select("#parallelSVG")
    .attr("width", w)
    .attr("height", h+m[0])
    .append("svg:g")
    .attr("transform", "translate(" + 0 + "," + m[0] + ")");

// Load the data and visualization
// d3.json("data/nvdcve-1.0-2014.json", function (raw_data) {      // 2014 -> 653 CVEs
//d3.json("data/nvdcve-1.0-2016.json", function(raw_data) {
// d3.json("data/nvdcve-1.0-2017.json", function(raw_data) {  // 2017 -> 12,829 CVEs
d3.json("data/nvdcve-1.0-2018.json", function(raw_data) {

    // var data21 = raw_data.CVE_Items.filter(function(d) {return d.cve.problemtype.problemtype_data[0].description.length>1;})
    // var data22 = raw_data.CVE_Items.filter(function(d) {return d.cve.problemtype.problemtype_data.length>1;})
    //    var data33 = raw_data.CVE_Items.filter(function(d) {return d.cve.affects.vendor.vendor_data.length>2;})


    data = [];
    for (var i = 0; i < raw_data.CVE_Items.length; i++) {
        var d = raw_data.CVE_Items[i].impact.baseMetricV3;
        if (d != undefined) {
            var obj = {};
            if (raw_data.CVE_Items[i].cve == undefined)
                obj.name = "";

            else
                obj.name = raw_data.CVE_Items[i].cve.description.description_data[0].value;
            obj.group = d.cvssV3.baseSeverity;

            // obj._id = data.length;
            obj.cve = raw_data.CVE_Items[i].cve;
            obj.originalCVE = raw_data.CVE_Items[i];
            obj.impactScore = d.impactScore;
            obj.exploitabilityScore = d.exploitabilityScore;
            obj.baseScore = d.cvssV3.baseScore;
            data.push(obj);
        }
    }

    // network *************************************************************************************************
    processNetwork();

    // Compute vendor order for Parallel Coordinates *****************************************************************************
    var data2 = [];
    data.forEach(function (d) {
        data2.push(d);
    });
    data2.sort(function (a, b) {
        if (a.vendorNode.data && b.vendorNode.data)
            return a.vendorNode.data.length < b.vendorNode.data.length ? -1 : 1;
        else if (a.vendorNode.data)
            return 1;
        else if (b.vendorNode.data)
            return -1;
        else
            return -1;
    });

    var listVendor = {};
    var count = 0;
    data2.forEach(function (d) {
        if (d.vendorNode.name == undefined) {
            if (listVendor["undefined"] == undefined) {
                listVendor["undefined"] = {};
                listVendor["undefined"].references = [];
            }
            listVendor["undefined"].references.push(d);
            listVendor["undefined"].order = count;
            d.vendor = count;
        }
        else if (listVendor[d.vendorNode.name] == undefined) {
            listVendor[d.vendorNode.name] = {};
            listVendor[d.vendorNode.name].references = [];
            listVendor[d.vendorNode.name].references.push(d);
            count++;
            listVendor[d.vendorNode.name].order = count;
            d.vendor = count;
        }
        else {
            listVendor[d.vendorNode.name].references.push(d);
            d.vendor = listVendor[d.vendorNode.name].order;
        }
    });

    // Compute PRODUCT for Parallel Coordinates *****************************************************************************
    var data2a = [];
    data.forEach(function (d) {
        data2a.push(d);
    });
    data2a.sort(function (a, b) {
        if (a.productNode && a.productNode.data && b.productNode && b.productNode.data)
            return a.productNode.data.length < b.productNode.data.length ? -1 : 1;
        else if (a.productNode && a.productNode.data)
            return 1;
        else if (b.productNode && b.productNode.data)
            return -1;
        else
            return -1;
    });

    var listProduct = {};
    var count = 0;
    data2a.forEach(function (d) {
        if (d.productNode == undefined || d.productNode.name == undefined) {
            if (listProduct["undefined"] == undefined) {
                listProduct["undefined"] = {};
                listProduct["undefined"].references = [];
            }
            listProduct["undefined"].references.push(d);
            listProduct["undefined"].order = count;
            d.product = count;
        }
        else if (listProduct[d.productNode.name] == undefined) {
            listProduct[d.productNode.name] = {};
            listProduct[d.productNode.name].references = [];
            listProduct[d.productNode.name].references.push(d);
            count++;
            listProduct[d.productNode.name].order = count;
            d.product = count;
        }
        else {
            listProduct[d.productNode.name].references.push(d);
            d.product = listProduct[d.productNode.name].order;
        }
    });


    // Compute Vulnerability type order for Parallel Coordinates *****************************************************************************
    var data3 = [];
    data.forEach(function (d) {
        data3.push(d);
    });
    data3.sort(function (a, b) {
        if (a.problemNode.data && b.problemNode.data)
            return a.problemNode.data.length < b.problemNode.data.length ? -1 : 1;
        else if (a.problemNode.data)
            return 1;
        else if (b.problemNode.data)
            return -1;
        else
            return -1;
    });

    var listProblem = {};
    var count = 0;
    data3.forEach(function (d, i) {
        if (d.problemNode.name == undefined) {
            if (listProblem["undefined"] == undefined) {
                listProblem["undefined"] = {};
                listProblem["undefined"].references = [];
            }
            listProblem["undefined"].references.push(d);
            listProblem["undefined"].order = count;
            d.vulnerability_type = count;
        }
        else if (listProblem[d.problemNode.name] == undefined) {
            listProblem[d.problemNode.name] = {};
            listProblem[d.problemNode.name].references = [];
            listProblem[d.problemNode.name].references.push(d);
            count++;
            listProblem[d.problemNode.name].order = count;
            d.vulnerability_type = count;
        }
        else {
            listProblem[d.problemNode.name].references.push(d);
            d.vulnerability_type = listProblem[d.problemNode.name].order;
        }
    });


    // Extract the list of numerical dimensions and create a scale for each.
    xscale.domain(dimensions = d3.keys(data[0]).filter(function (k) {
        return (_.isNumber(data[0][k])) && (yscale[k] = d3.scale.linear()
            .domain(d3.extent(data, function (d) {
                return +d[k];
            }))
            .range([h, 0]));
    }).sort());

    // Add a group element for each dimension.
    var g = svg.selectAll(".dimension")
        .data(dimensions)
        .enter().append("svg:g")
        .attr("class", "dimension")
        .attr("transform", function (d) {
            return "translate(" + xscale(d) + ")";
        })
        .call(d3.behavior.drag()
            .on("dragstart", function (d) {
                dragging[d] = this.__origin__ = xscale(d);
                this.__dragged__ = false;
                d3.select("#foreground").style("opacity", "0.35");
            })
            .on("drag", function (d) {
                dragging[d] = Math.min(w, Math.max(0, this.__origin__ += d3.event.dx));
                dimensions.sort(function (a, b) {
                    return position(a) - position(b);
                });
                xscale.domain(dimensions);
                g.attr("transform", function (d) {
                    return "translate(" + position(d) + ")";
                });
                brush_count++;
                this.__dragged__ = true;

                // Feedback for axis deletion if dropped
                if (dragging[d] < 12 || dragging[d] > w - 12) {
                    d3.select(this).select(".background").style("fill", "#b00");
                } else {
                    d3.select(this).select(".background").style("fill", null);
                }
            })
            .on("dragend", function (d) {
                if (!this.__dragged__) {
                    // no movement, invert axis
                    var extent = invert_axis(d);

                } else {
                    // reorder axes
                    d3.select(this).transition().attr("transform", "translate(" + xscale(d) + ")");

                    var extent = yscale[d].brush.extent();
                }

                // remove axis if dragged all the way left
                if (dragging[d] < 12 || dragging[d] > w - 12) {
                    remove_axis(d, g);
                }

                // TODO required to avoid a bug
                xscale.domain(dimensions);
                update_ticks(d, extent);

                // rerender
                d3.select("#foreground").style("opacity", null);
                brush();
                delete this.__dragged__;
                delete this.__origin__;
                delete dragging[d];
            }))

    // Add an axis and title.
    g.append("svg:g")
        .attr("class", "axis")
        .attr("transform", "translate(0,0)")
        .each(function (d) {
            d3.select(this).call(axis.scale(yscale[d]));
        })
        .append("svg:text")
        .attr("text-anchor", "middle")
        .attr("y", -14)
        .attr("x", 0)
        .attr("class", "label")
        .text(String)
        .append("title")
        .text("Click to invert. Drag to reorder");

    // Add and store a brush for each axis.
    g.append("svg:g")
        .attr("class", "brush")
        .each(function (d) {
            d3.select(this).call(yscale[d].brush = d3.svg.brush().y(yscale[d]).on("brush", brush));
        })
        .selectAll("rect")
        .style("visibility", null)
        .attr("x", -23)
        .attr("width", 36)
        .append("title")
        .text("Drag up or down to brush along this axis");

    g.selectAll(".extent")
        .append("title")
        .text("Drag or resize this filter");


    legend = create_legend(colors, brush);

    // Render full foreground
    brush();

});

// copy one canvas to another, grayscale
function gray_copy(source, target) {
    var pixels = source.getImageData(0, 0, w, h);
    target.putImageData(grayscale(pixels), 0, 0);
}

// http://www.html5rocks.com/en/tutorials/canvas/imagefilters/
function grayscale(pixels, args) {
    var d = pixels.data;
    for (var i = 0; i < d.length; i += 4) {
        var r = d[i];
        var g = d[i + 1];
        var b = d[i + 2];
        // CIE luminance for the RGB
        // The human eye is bad at seeing red and blue, so we de-emphasize them.
        var v = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        d[i] = d[i + 1] = d[i + 2] = v
    }
    return pixels;
};


function create_legend(colors, brush) {
    // create legend
    var legend_data = d3.select("#legend")
        .html("")
        .selectAll(".row")
        .data(_.keys(colors))
    // debugger;

    // filter by group
    var legend = legend_data
        .enter().append("div")
        .attr("title", "Hide group")
        .on("click", function (d) {
            // toggle food group
            if (_.contains(excluded_groups, d)) {
                d3.select(this).attr("title", "Hide group")
                excluded_groups = _.difference(excluded_groups, [d]);
                brush();
            } else {
                d3.select(this).attr("title", "Show group")
                excluded_groups.push(d);
                brush();
            }
        });

    legend
        .append("span")
        .style("background", function (d, i) {
            return color(d, 0.85)
        })
        .attr("class", "color-bar");

    legend
        .append("span")
        .attr("class", "tally")
        .text(function (d, i) {
            return 0
        });

    legend
        .append("span")
        .text(function (d, i) {
            return " " + d
        });

    return legend;
}

// render polylines i to i+render_speed 
function render_range(selection, i, max, opacity) {
    selection.slice(i, max).forEach(function (d) {
        path(d, foreground, color(d.group, opacity));
    });
};

// simple data table
function data_table(sample) {
    // sort by first column
    var sample = sample.sort(function (a, b) {
        var col = d3.keys(a)[0];
        return a[col] < b[col] ? -1 : 1;
    });

    var table = d3.select("#food-list")
        .html("")
        .selectAll(".row")
        .data(sample)
        .enter().append("div")
        .on("mouseover", highlight)
        .on("mouseout", unhighlight);

    table
        .append("span")
        .attr("class", "color-block")
        .style("background", function (d) {
            return color(d.group, 0.85)
        })

    table
        .append("span")
        .text(function (d) {
            return d.name;
        })
}

// Adjusts rendering speed 
function optimize(timer) {
    var delta = (new Date()).getTime() - timer;
    render_speed = Math.max(Math.ceil(render_speed / delta), 8);
    render_speed = Math.min(render_speed, 10);
    return (new Date()).getTime();
}

// Feedback on rendering progress
function render_stats(i, n, render_speed) {
    d3.select("#rendered-count").text(i);
    d3.select("#rendered-bar")
        .style("width", (100 * i / n) + "%");
    d3.select("#render-speed").text(render_speed);
}

// Feedback on selection
function selection_stats(opacity, n, total) {
    d3.select("#data-count").text(total);
    d3.select("#selected-count").text(n);
    d3.select("#selected-bar").style("width", (100 * n / total) + "%");
    d3.select("#opacity").text(("" + (opacity * 100)).slice(0, 4) + "%");
}

// Highlight single polyline
function highlight(d) {
    d3.select("#foreground").style("opacity", "0.25");
    d3.selectAll(".row").style("opacity", function (p) {
        return (d.group == p) ? null : "0.3"
    });
    path(d, highlighted, color(d.group, 1));
}

// Remove highlight
function unhighlight() {
    d3.select("#foreground").style("opacity", null);
    d3.selectAll(".row").style("opacity", null);
    highlighted.clearRect(0, 0, w, h);
}

function invert_axis(d) {
    // save extent before inverting
    if (!yscale[d].brush.empty()) {
        var extent = yscale[d].brush.extent();
    }
    if (yscale[d].inverted == true) {
        yscale[d].range([h, 0]);
        d3.selectAll('.label')
            .filter(function (p) {
                return p == d;
            })
            .style("text-decoration", null);
        yscale[d].inverted = false;
    } else {
        yscale[d].range([0, h]);
        d3.selectAll('.label')
            .filter(function (p) {
                return p == d;
            })
            .style("text-decoration", "underline");
        yscale[d].inverted = true;
    }
    return extent;
}


function path(d, ctx, color) {
    if (color) ctx.strokeStyle = color;
    ctx.beginPath();
    var x0 = xscale(0),
        y0 = yscale[dimensions[0]](d[dimensions[0]]);   // left edge
    ctx.moveTo(x0, y0);
    dimensions.map(function (p, i) {
        var gap =0;
        if (i==0)
            gap=(width-600)/24;
        var x = xscale(p)-gap,
            y = yscale[p](d[p]);
        var cp1x = x - 0.8 * (x - x0)-gap;
        var cp1y = y0;
        var cp2x = x - 0.2 * (x - x0)-gap;
        var cp2y = y;
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y);
        x0 = x;
        y0 = y;
    });
    ctx.lineTo(x0 - 15, y0);                               // right edge
    ctx.stroke();
};

function color(d, a) {
    var c = colors[d];
    return ["hsla(", c[0], ",", c[1], "%,", c[2], "%,", a, ")"].join("");
}

function position(d) {
    var v = dragging[d];
    return v == null ? xscale(d) : v;
}

// Handles a brush event, toggling the display of foreground lines.
// TODO refactor
function brush() {
    brush_count++;
    var actives = dimensions.filter(function (p) {
            return !yscale[p].brush.empty();
        }),
        extents = actives.map(function (p) {
            return yscale[p].brush.extent();
        });

    // hack to hide ticks beyond extent
    var b = d3.selectAll('.dimension')[0]
        .forEach(function (element, i) {
            var dimension = d3.select(element).data()[0];
            if (_.include(actives, dimension)) {
                var extent = extents[actives.indexOf(dimension)];
                d3.select(element)
                    .selectAll('text')
                    .style('font-weight', 'bold')
                    .style('font-size', '13px')
                    .style('display', function () {
                        var value = d3.select(this).data();
                        return extent[0] <= value && value <= extent[1] ? null : "none"
                    });
            } else {
                d3.select(element)
                    .selectAll('text')
                    .style('font-size', null)
                    .style('font-weight', null)
                    .style('display', null);
            }
            d3.select(element)
                .selectAll('.label')
                .style('display', null);
        });
    ;

    // bold dimensions with label
    d3.selectAll('.label')
        .style("font-weight", function (dimension) {
            if (_.include(actives, dimension)) return "bold";
            return null;
        });

    // Get lines within extents
    var selected = [];
    data
        .filter(function (d) {
            return !_.contains(excluded_groups, d.group);
        })
        .map(function (d) {
            return actives.every(function (p, dimension) {
                return extents[dimension][0] <= d[p] && d[p] <= extents[dimension][1];
            }) ? selected.push(d) : null;
        });

    // free text search
    var query = d3.select("#search")[0][0].value;
    if (query.length > 0) {
        selected = search(selected, query);
    }

    if (selected.length < data.length && selected.length > 0) {
        d3.select("#keep-data").attr("disabled", null);
        d3.select("#exclude-data").attr("disabled", null);
    } else {
        d3.select("#keep-data").attr("disabled", "disabled");
        d3.select("#exclude-data").attr("disabled", "disabled");
    }
    ;

    // total by food group
    var tallies = _(selected)
        .groupBy(function (d) {
            return d.group;
        })

    // include empty groups
    _(colors).each(function (v, k) {
        tallies[k] = tallies[k] || [];
    });

    legend
        .style("text-decoration", function (d) {
            return _.contains(excluded_groups, d) ? "line-through" : null;
        })
        .attr("class", function (d) {
            return (tallies[d].length > 0)
                ? "row"
                : "row off";
        });

    legend.selectAll(".color-bar")
        .style("width", function (d) {
            return Math.ceil(400 * tallies[d].length / data.length) + "px"
        });

    legend.selectAll(".tally")
        .text(function (d, i) {
            return tallies[d].length
        });

    // Tommy 2018, Word Cloud  **************************************
    // var text_string = "";
    // for (var i = 0; i < selected.length; i++) {
    //     text_string += selected[i].name + " ";
    // }
    // drawWordCloud(text_string);

    //Vung's word cloud
    cves = modifiedCVEsToOriginalCVEs(selected);
    loadCloudCVEs(cloudViewOptions.map(d=>d.key), draw);

    // Tommy 2018, NETWORK     **************************************
    processNetwork(selected);
    drawNetwork();

    // Render selected lines
    paths(selected, foreground, brush_count, true);
}

// render a set of polylines on a canvas
function paths(selected, ctx, count) {
    var n = selected.length,
        i = 0,
        opacity = d3.min([2 / Math.pow(n, 0.1), 1]),
        timer = (new Date()).getTime();

    selection_stats(opacity, n, data.length)

    shuffled_data = _.shuffle(selected);

    data_table(shuffled_data.slice(0, 40));

    ctx.clearRect(0, 0, w + 1, h + 1);

    // render all lines until finished or a new brush event
    function animloop() {
        if (i >= n || count < brush_count) return true;
        var max = d3.min([i + render_speed, n]);
        render_range(shuffled_data, i, max, opacity);
        render_stats(max, n, render_speed);
        i = max;
        timer = optimize(timer);  // adjusts render_speed
    };

    d3.timer(animloop);
}

// transition ticks for reordering, rescaling and inverting
function update_ticks(d, extent) {
    // update brushes
    if (d) {
        var brush_el = d3.selectAll(".brush")
            .filter(function (key) {
                return key == d;
            });
        // single tick
        if (extent) {
            // restore previous extent
            brush_el.call(yscale[d].brush = d3.svg.brush().y(yscale[d]).extent(extent).on("brush", brush));
        } else {
            brush_el.call(yscale[d].brush = d3.svg.brush().y(yscale[d]).on("brush", brush));
        }
    } else {
        // all ticks
        d3.selectAll(".brush")
            .each(function (d) {
                d3.select(this).call(yscale[d].brush = d3.svg.brush().y(yscale[d]).on("brush", brush));
            })
    }

    brush_count++;

    show_ticks();

    // update axes
    d3.selectAll(".axis")
        .each(function (d, i) {
            // hide lines for better performance
            d3.select(this).selectAll('line').style("display", "none");

            // transition axis numbers
            d3.select(this)
                .transition()
                .duration(720)
                .call(axis.scale(yscale[d]));

            // bring lines back
            d3.select(this).selectAll('line').transition().delay(800).style("display", null);

            d3.select(this)
                .selectAll('text')
                .style('font-weight', null)
                .style('font-size', null)
                .style('display', null);
        });
}

// Rescale to new dataset domain
function rescale() {
    // reset yscales, preserving inverted state
    dimensions.forEach(function (d, i) {
        if (yscale[d].inverted) {
            yscale[d] = d3.scale.linear()
                .domain(d3.extent(data, function (p) {
                    return +p[d];
                }))
                .range([0, h]);
            yscale[d].inverted = true;
        } else {
            yscale[d] = d3.scale.linear()
                .domain(d3.extent(data, function (p) {
                    return +p[d];
                }))
                .range([h, 0]);
        }
    });

    update_ticks();

    // Render selected data
    paths(data, foreground, brush_count);
}

// Get polylines within extents
function actives() {
    var actives = dimensions.filter(function (p) {
            return !yscale[p].brush.empty();
        }),
        extents = actives.map(function (p) {
            return yscale[p].brush.extent();
        });

    // filter extents and excluded groups
    var selected = [];
    data
        .filter(function (d) {
            return !_.contains(excluded_groups, d.group);
        })
        .map(function (d) {
            return actives.every(function (p, i) {
                return extents[i][0] <= d[p] && d[p] <= extents[i][1];
            }) ? selected.push(d) : null;
        });

    // free text search
    var query = d3.select("#search")[0][0].value;
    if (query > 0) {
        selected = search(selected, query);
    }

    return selected;
}

// Export data
function export_csv() {
    var keys = d3.keys(data[0]);
    var rows = actives().map(function (row) {
        return keys.map(function (k) {
            return row[k];
        })
    });
    var csv = d3.csv.format([keys].concat(rows)).replace(/\n/g, "<br/>\n");
    var styles = "<style>body { font-family: sans-serif; font-size: 12px; }</style>";
    window.open("text/csv").document.write(styles + csv);
}

// scale to window size
window.onresize = function () {
    // width = document.body.clientWidth,
    //     height = d3.max([document.body.clientHeight - 500, 220]);
    //
    // w = width - m[1] - m[3],
    //     h = height - m[0] - m[2];
    //
    // d3.select("#chart")
    //     .style("height", (h + m[0] + m[2]) + "px")
    //
    // d3.selectAll("canvas")
    //     .attr("width", w)
    //     .attr("height", h)
    //     .style("padding", m.join("px ") + "px");
    //
    // d3.select("#parallelSVG")
    //     .attr("width", w )
    //     .attr("height", h)
    //     .select("g");
    //     //.attr("transform", "translate(" + m[3] + "," + m[0] + ")");
    //
    // xscale = d3.scale.ordinal().rangePoints([0, w], 1).domain(dimensions);
    // dimensions.forEach(function (d) {
    //     yscale[d].range([h, 0]);
    // });
    //
    // d3.selectAll(".dimension")
    //     .attr("transform", function (d) {
    //         return "translate(" + xscale(d) + ")";
    //     })
    // // update brush placement
    // d3.selectAll(".brush")
    //     .each(function (d) {
    //         d3.select(this).call(yscale[d].brush = d3.svg.brush().y(yscale[d]).on("brush", brush));
    //     })
    // brush_count++;
    //
    // // update axis placement
    // axis = axis.ticks(1 + height / 50),
    //     d3.selectAll(".axis")
    //         .each(function (d) {
    //             d3.select(this).call(axis.scale(yscale[d]));
    //         });
    //
    // // render data
    // brush();
};

// Remove all but selected from the dataset
function keep_data() {
    new_data = actives();
    if (new_data.length == 0) {
        alert("I don't mean to be rude, but I can't let you remove all the data.\n\nTry removing some brushes to get your data back. Then click 'Keep' when you've selected data you want to look closer at.");
        return false;
    }
    data = new_data;
    rescale();
}

// Exclude selected from the dataset
function exclude_data() {
    new_data = _.difference(data, actives());
    if (new_data.length == 0) {
        alert("I don't mean to be rude, but I can't let you remove all the data.\n\nTry selecting just a few data points then clicking 'Exclude'.");
        return false;
    }
    data = new_data;
    rescale();
}

function remove_axis(d, g) {
    dimensions = _.difference(dimensions, [d]);
    xscale.domain(dimensions);
    g.attr("transform", function (p) {
        return "translate(" + position(p) + ")";
    });
    g.filter(function (p) {
        return p == d;
    }).remove();
    update_ticks();
}

d3.select("#keep-data").on("click", keep_data);
d3.select("#exclude-data").on("click", exclude_data);
d3.select("#export-data").on("click", export_csv);
d3.select("#search").on("keyup", brush);


// Appearance toggles
d3.select("#hide-ticks").on("click", hide_ticks);
d3.select("#show-ticks").on("click", show_ticks);
d3.select("#dark-theme").on("click", dark_theme);
d3.select("#light-theme").on("click", light_theme);

function hide_ticks() {
    d3.selectAll(".axis g").style("display", "none");
    //d3.selectAll(".axis path").style("display", "none");
    d3.selectAll(".background").style("visibility", "hidden");
    d3.selectAll("#hide-ticks").attr("disabled", "disabled");
    d3.selectAll("#show-ticks").attr("disabled", null);
};

function show_ticks() {
    d3.selectAll(".axis g").style("display", null);
    //d3.selectAll(".axis path").style("display", null);
    d3.selectAll(".background").style("visibility", null);
    d3.selectAll("#show-ticks").attr("disabled", "disabled");
    d3.selectAll("#hide-ticks").attr("disabled", null);
};

function dark_theme() {
    d3.select("body").attr("class", "dark");
    d3.selectAll("#dark-theme").attr("disabled", "disabled");
    d3.selectAll("#light-theme").attr("disabled", null);
}

function light_theme() {
    d3.select("body").attr("class", null);
    d3.selectAll("#light-theme").attr("disabled", "disabled");
    d3.selectAll("#dark-theme").attr("disabled", null);
}

function search(selection, str) {
    pattern = new RegExp(str, "i")
    return _(selection).filter(function (d) {
        return pattern.exec(d.name);
    });
}

