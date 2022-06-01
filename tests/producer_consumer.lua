function producer()
    return 44
end

function consumer()
    val = 42
   --val = producer()
  --  val = prod_fn()
    return val % 5
end
