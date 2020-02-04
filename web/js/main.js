
system.data.init('json_data')
  .then(() => {
    system.state.init()
    system.stats.init()
  })