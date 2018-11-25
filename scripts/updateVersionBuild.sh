line=$(head -n 1 VERSION)
bumpversion --current-version $line patch setup.py --allow-dirty
bumpversion --current-version $line patch VERSION --allow-dirty