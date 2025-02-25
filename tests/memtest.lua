local tab = {}

vals = 1000000
for i = 1, vals do
    tab[i] = "menu"
end
print(collectgarbage("count"))
