import numpy as np
import matplotlib.pyplot as plt
def perform_pca(X, n_components=2):
    X_meaned = X - np.mean(X, axis=0)
    covariance_matrix = np.cov(X_meaned, rowvar=False)
    eigen_values, eigen_vectors = np.linalg.eigh(covariance_matrix)
    sorted_index = np.argsort(eigen_values)[::-1]
    sorted_eigenvalues = eigen_values[sorted_index]
    sorted_eigenvectors = eigen_vectors[:, sorted_index]
    eigenvector_subset = sorted_eigenvectors[:, :n_components]
    X_reduced = np.dot(X_meaned, eigenvector_subset)
    
    return X_reduced, sorted_eigenvalues, sorted_eigenvectors

data = np.array([[5.1, 3.5, 1.4, 0.2], 
                 [4.7, 3.2, 1.3, 0.3], 
                 [4.9, 3.6, 1.2, 0.2], 
                 [6.0, 3.0, 5.2, 2.3], 
                 [5.9, 3.1, 5.1, 1.8], 
                 [5.8, 2.9, 5.3, 2.2]])

reduced_data, eigenvalues, eigenvectors = perform_pca(data, n_components=2)

print("Reduced Data (2D):\n", reduced_data)

def plot_2d_scatter(reduced_data):
    plt.scatter(reduced_data[:, 0], reduced_data[:, 1], c='blue', marker='o')
    plt.title('PCA - 2D Scatter Plot')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.grid(True)
    plt.show()
plot_2d_scatter(reduced_data)
