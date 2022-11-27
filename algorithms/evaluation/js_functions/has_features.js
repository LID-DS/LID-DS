/**
 * MongoDB custom function to query experiments by features
 * Traverses the dependency graph (nodes and links) and checks weather a path containing the specified algo_features exists
 *
 * @param {Array} nodes dependency graph nodes
 * @param {Array} links dependency graph links
 * @param {string} algorithm base algorithm
 * @param {Object<Array<string>>} algo_features dictionary features per algorithm to include
 * @param {boolean} exact if true match features exactly otherwise ignore remaining nodes
 * @returns {boolean} true if dependency graph contains specified features
 */
function has_features(nodes, links, algorithm, algo_features, exact) {
    const features = algo_features[algorithm]
    const nodes_map = Object.fromEntries(nodes.map((node) => [node.id, node]))
    let previous_target_id = nodes[0].id
    let unmatched_nodes = false
    let matched = 0;
    for (let i = 0; i < features.length - 1; i++) {
        const source = features[i]

        const target = features[i + 1]
        let found_target
        let found_target_id
        for (let link of links) {
            let source_node = nodes_map[link.source]
            if (source_node.name === source && link.source === previous_target_id) {
                found_target = nodes_map[link.target].name
                found_target_id = link.target
                if (found_target === target) {
                    previous_target_id = found_target_id
                    break
                }
            }
        }
        if (!found_target || found_target !== target) {
            unmatched_nodes = true
            break
        }
        matched++
    }

    if (exact) {
        unmatched_nodes = unmatched_nodes || matched < nodes.length
    }
    return !unmatched_nodes
}
