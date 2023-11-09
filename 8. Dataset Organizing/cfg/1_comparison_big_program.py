import os
import networkx as nx
from multiprocessing import Pool, cpu_count
from time import time
from tqdm import tqdm


def check_isomorphism(args):
    baseline_path, option_path, bin, dot_file, log_file = args
    # option_path = option_path.split('/')[-1].split('_')[-2]

    try:
        if dot_file != "ngx_vslprintf.dot":
            G1 = nx.DiGraph(nx.drawing.nx_agraph.read_dot(
                f"{baseline_path}/{dot_file}"))
            G2 = nx.DiGraph(nx.drawing.nx_agraph.read_dot(
                f"{option_path}/{bin}/{dot_file}"))
            
            nodes_g1 = G1.number_of_nodes() 
            nodes_g2 = G2.number_of_nodes()
            edges_g1 = G1.number_of_edges() 
            edges_g2 = G2.number_of_edges()

            print(f"{baseline_path}/{dot_file} {(G1.number_of_edges() , G1.number_of_edges())} ------ {option_path}/{bin}/{dot_file} {G2.number_of_nodes(), G2.number_of_edges()}")
            # Check if number of nodes and edges are equal
            if G1.number_of_nodes() != G2.number_of_nodes() and G1.number_of_edges() != G2.number_of_edges():
                with open(log_file, "a") as f:
                    f.write(
                        f"no, # of nodes & # of edges, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")
            elif G1.number_of_nodes() != G2.number_of_nodes():
                with open(log_file, "a") as f:
                    f.write(f"no, # of nodes, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")
            elif G1.number_of_edges() != G2.number_of_edges():
                with open(log_file, "a") as f:
                    f.write(f"no, # of edges, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")

            else:
                # Check if degree sequences are equal
                deg_seq1 = sorted(list(dict(G1.degree()).values()))
                deg_seq2 = sorted(list(dict(G2.degree()).values()))
                if deg_seq1 != deg_seq2:
                    with open(log_file, "a") as f:
                        f.write(
                            f"no, degree sequences, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)},  {option_path}/{bin}/{dot_file}\n")
                else:
                    # Check if there is a bijection that preserves adjacency
                    start_time = time()
                    if nx.is_isomorphic(G1, G2):
                        elapsed_time = time() - start_time
                        print("1 >>>> ",elapsed_time)
                        if elapsed_time > 60:  # if the comparison takes more than 60 seconds, skip it
                            print("2 >>>> ",elapsed_time)
                            with open(log_file, "a") as f:
                                f.write(
                                    f"skipped, took too long, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")
                        else:

                            with open(log_file, "a") as f:
                                # f.write(f"****** isomorphic {option_path}/{bin}/{dot_file} ******\n")
                                f.write(
                                    f"yes, is_isomorphic, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")
                    else:
                        with open(log_file, "a") as f:
                            f.write(
                                f"no, not is_isomorphic, {(nodes_g1, edges_g1)}, {(nodes_g2, edges_g2)}, {option_path}/{bin}/{dot_file}\n")

    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"no, removed, {option_path}/{bin}/{dot_file}\n")


def main():
    baseline_binaries_path = "/home/omar/analysis-binaries/transformation/putty_cfg/clang_baseline"
    options__binaries_path = "/home/omar/analysis-binaries/transformation/putty_cfg"
    log_file = "logs_comparison_fast_puttygen.txt"

    # create list of tuples for each dot file
    file_list = []

    flag = 1

    if flag == 0:
        # for all programe
        for bin in tqdm(os.listdir(baseline_binaries_path)):
            if bin == "puttygen":
                baseline_path = f"{baseline_binaries_path}/{bin}"
                options_path = f"{options__binaries_path}"
                for option_path in os.listdir(options_path):
                    for dot_file in os.listdir(baseline_path):
                        file_list.append(
                            (baseline_path, f"{options_path}/{option_path}", bin, dot_file, log_file))
    else:
        # for one program
        

        compiliers = ["gcc","clang"]
        optimizations = ["O0_fno", "O0","O1","O2","O3"]
        for comp in compiliers:
            # if comp == "clang":
                for opt in optimizations:
                    if opt == "O0_fno":
                        print(comp,opt)
                        file_list = []
                        baseline_path = f"/home/omar/analysis-binaries/transformation/big_program/putty/putty_cfg/executables/puttygen_exec/{comp}/putty_{comp}_{opt}_/"
                        options_path = f"/home/omar/analysis-binaries/transformation/big_program/putty/putty_cfg/executables/puttygen_exec/{comp}/"
                        log_file = f"/home/omar/analysis-binaries/transformation/big_program/putty/logs/{comp}_flags_{opt}.txt"
                        # print(baseline_path)
                        # break
                        for option_path in os.listdir(options_path):
                            # print("_".join(option_path.split("_")[2:4]))
                            # print("O0_fno" == "_".join(option_path.split("_")[2:4])==True)
                            if opt == option_path.split("_")[2] and option_path != f"putty_{comp}_{opt}_":
                                print("no")
                                # for dot_file in os.listdir(baseline_path):
                                #     file_list.append(
                                #         (baseline_path, f"{options_path}/{option_path}", "/", dot_file, log_file))
                            elif opt == "O0_fno" and "O0_fno" == "_".join(option_path.split("_")[2:4]):
                                print(baseline_path, f"{options_path}/{option_path}")
                                # for dot_file in os.listdir(baseline_path):
                                #     file_list.append(
                                #         (baseline_path, f"{options_path}/{option_path}", "/", dot_file, log_file))


                        # break 
                        # run check_isomorphism in parallel using multiple processes
                        with Pool(cpu_count()) as pool:
                            pool.map(check_isomorphism, file_list)


if __name__ == "__main__":
    # os.system(": > /home/omar/analysis-binaries/transformation/big_program/puttygen_clang_flags.txt")
    main()
