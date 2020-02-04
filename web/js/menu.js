if (window.system == undefined) window.system = {}
system.menu = (function() {
    Waves.attach(".menu-toggle", "waves-light");
    Waves.init();
    var that = this;
    this.overlay = d3.select(".overlay-div")
        .on("click", function(){
            that.hideOverlay();
            that.left.close();
            that.right.close();
        })
    this.showOverlay = function(){
        this.overlay.style("display", "block")
    }
    this.hideOverlay = function(){
        this.overlay.style("display", "none")
    }
    /*
    */
    this.left = (function(){
        var div = d3.select(".left-menu");
        this.open = function(){
            that.showOverlay();
            div.transition().duration(500).style("left", "0px");
        }
        this.close = function(){
            div.style("left", "-300px")
            that.hideOverlay()
        }
        return this;
    }).call({})
    /*
    */
    this.right = (function(){
        var width = 300;
        var div = d3.select(".right-menu");
        this.open = function(){
            that.showOverlay();
            div.transition().duration(500).style("right", "0px");
        }
        this.close = function(){
            div.style("right", "-300px")
            that.hideOverlay()
        }
        return this;
    }).call({})
    /*
    */
   return this;
}).call({})