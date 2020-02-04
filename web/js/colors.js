if (window.system == undefined) window.system = {}
system.colors = (function() {
    this.colorLinearScale = (colorInterpolator) => {
        var linearScale = d3.scaleLinear()
        var forceOutFn = null
        var fn = (d) => {
            if(forceOutFn != undefined) return (typeof forceOutFn === "function") ? forceOutFn(d) : forceOutFn
            if(linearScale.domain()[0] == linearScale.domain()[1]) return colorInterpolator(1)
            return colorInterpolator(linearScale(d)) 
        }
        fn.domain = (d) => { 
            if(d == undefined) return linearScale.domain()
            linearScale.domain(d)
            return fn
        }
        fn.range = (d) => { 
            if(d == undefined) return linearScale.range()
            linearScale.range(d)
            return fn
        }
        fn.forceOut = (d) => {
            forceOutFn = d
            return fn
        }
        return fn
    }
    /*
    *
    */
    this.cfgEdgeColor = () => {
        return this.colorLinearScale(d3.interpolateMagma).range([0.9, 0])
        //d3.interpolateOrRd
    }
    this.cfgForksColor = () => {
        return this.colorLinearScale(d3.interpolateBlues).range([0.2, 0.8])
    }
    this.cfgForksColorFixed = "#4292c6"
    this.cfgSymbolsColor = () => {
        return this.colorLinearScale(d3.interpolateGreens).range([0.2, 0.8])
    }
    this.cfgSymbolsColorFixed = "#238b45"
    /*
    *
    */
    this.treeForkingBlocks = () => {
        const range = JSON.parse(JSON.stringify(['#fbb4ae','#b3cde3','#decbe4','#fed9a6','#ffffcc','#e5d8bd','#fddaec']))
        return d3.scaleOrdinal().range(range).unknown('gray')
    }
    this.treeForkingSymbols = () => {
        const range = JSON.parse(JSON.stringify(['#fbb4ae','#b3cde3','#decbe4','#fed9a6','#ffffcc','#e5d8bd','#fddaec']))
        return d3.scaleOrdinal().range(range).unknown('gray')
    }
    this.treeBlocksCatColor = () => {
        return this.colorLinearScale(d3.interpolateGreys).range([0.2, 0.8])
    }
    /*
    *
    */
    return this
}).call({})