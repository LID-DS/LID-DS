/**
 * MongoDB custom function to get the config value for specified config alias
 * Traverses the dependency graph (nodes and links) and the group_by_config graph.
 * When it finds the config alias in the group_by_config graph it returns the value of the corresponding config stored in the db
 *
 * @param {Array} nodes dependency graph nodes
 * @param {Array} links dependency graph links
 * @param {string} algorithm base algorithm
 * @param {Object} group_by_config dictionary of config aliases per algorithm
 * @param {string} config_alias the alias of the config value to search
 * @returns {any} the config value for the config alias if a path to the config value exists else undefined
 */
function get_config_value(nodes, links, algorithm, group_by_config, config_alias) {
    if (!(algorithm in group_by_config)) return

    const nodes_map = Object.fromEntries(nodes.map((node) => [node.id, node]))
    group_by_config = group_by_config[algorithm]
    let initial_id = nodes[0].id
    let current_config = nodes[0]
    return get_config(links, [group_by_config], current_config, initial_id, config_alias, true)

    function get_config(links, config_group_list, current_config, current_id, config_alias, first) {
        for (let config of config_group_list) {
            let target_name = config.name
            let target = get_target(links, current_config.name, target_name, current_id)

            if (first) {
                target = current_config
            }

            if (!target) return

            for (let key in config) {
                if (Array.isArray(config[key])) {
                    return get_config(links, config[key], target, target.id, config_alias)
                }
                if (config[key] === config_alias && key in target["config"]) {
                    return target["config"][key]
                }
            }
        }
    }

    function get_target(links, source_name, target_name, source_id) {
        let previous_target_id = source_id
        let found_target = null
        let found_target_id = null
        for (let i = 0; i < links.length; i++) {
            let link = links[i]
            let source_node = nodes_map[link.source]
            if (source_node.name === source_name && link.source === previous_target_id) {
                let target = nodes_map[link.target]
                found_target = target.name
                found_target_id = link.target
                if (found_target === target_name) {
                    links.splice(i, 1)
                    return target
                }
            }
        }
        return null
    }
}
